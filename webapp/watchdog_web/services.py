"""Operazioni comuni alle pagine e all'API: validazione, coda, riepiloghi, confronto."""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from risk_assessor.risk.areas import AREAS
from risk_assessor.risk.compare import check_of, finding_key

from watchdog_web import engine as eng
from watchdog_web import netpolicy
from watchdog_web.models import ACTIVE_STATES, AuditLog, Finding, Scan, Target, User
from watchdog_web.security import SecretBox

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_LABEL = {"CRITICAL": "Critico", "HIGH": "Alto", "MEDIUM": "Medio", "LOW": "Basso", "INFO": "Informazione"}
STATUS_LABEL = {"queued": "In coda", "running": "In corso", "done": "Completata",
                "failed": "Non riuscita", "cancelled": "Annullata"}
# Colonne della heatmap: le aree del report, senza quella di servizio.
HEATMAP_AREAS = [(k, v[0], v[1]) for k, v in AREAS.items() if k != "system"]
AREA_SHORT = {"access": "Accessi", "network": "Rete", "vulns": "Vulnerabilità", "malware": "Malware",
              "integrity": "Integrità", "hardening": "Hardening", "logging": "Log", "apps": "Applicazioni",
              "system": "Sistema"}
# Intestazioni corte per le colonne strette della heatmap (il nome intero è nel title).
AREA_HEAD = {**AREA_SHORT, "vulns": "Vulnerab.", "apps": "App"}
OPTION_LABELS = {
    "no_install": "Non installare nulla sul sistema (usa solo i tool già presenti)",
    "keep_tools": "Lascia installati i tool alla fine",
    "external_scan": "Scansione Nmap anche dall'esterno (dal Raspberry verso il sistema)",
    "allow_epel": "Su RHEL e derivate, consenti il repository EPEL per i tool mancanti",
}
MAX_QUEUED_PER_TARGET = 3

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}\$?$")
_NAME_RE = re.compile(r"^[\w .()\-]{1,80}$", re.UNICODE)


class Invalid(ValueError):
    """Dati non validi: il messaggio è per chi ha compilato il modulo."""


def audit(s: Session, user: User | None, action: str, detail: str = "", ip: str = "",
          username: str = "") -> None:
    s.add(AuditLog(user_id=user.id if user else None, username=user.username if user else username[:64],
                   action=action, detail=detail[:500], ip=ip[:64]))


# --------------------------------------------------------------------------- obiettivi

def check_private_key(text: str) -> None:
    """La chiave deve essere leggibile da Paramiko e senza passphrase."""
    import paramiko
    if "PRIVATE KEY" not in text:
        raise Invalid("La chiave privata non è nel formato atteso (deve iniziare con -----BEGIN … PRIVATE KEY-----).")
    last: Exception | None = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            cls.from_private_key(io.StringIO(text.strip() + "\n"))
            return
        except paramiko.PasswordRequiredException:
            raise Invalid("La chiave è protetta da passphrase: usane una senza passphrase, dedicata a WatchDog.") from None
        except Exception as e:      # tipo di chiave diverso: provo il successivo
            last = e
    raise Invalid(f"Chiave privata non leggibile ({type(last).__name__}). Sono supportate Ed25519, ECDSA e RSA.")


def apply_target_fields(s: Session, box: SecretBox, target: Target, data: dict, *, new: bool, settings) -> None:
    """Valida i campi e li scrive sull'obiettivo. Password e chiave vuote = non cambiare."""
    name = str(data.get("name", "")).strip()
    host = str(data.get("host", "")).strip()
    ssh_user = str(data.get("ssh_user", "")).strip()
    method = str(data.get("auth_method", "password")).strip()
    secret = str(data.get("secret", "") or "")
    sudo_password = str(data.get("sudo_password", "") or "")
    try:
        port = int(str(data.get("port", "22")).strip() or "22")
    except ValueError:
        raise Invalid("La porta deve essere un numero.") from None
    if not _NAME_RE.match(name):
        raise Invalid("Il nome è obbligatorio (massimo 80 caratteri: lettere, numeri, spazi, . - _ parentesi).")
    if not _HOST_RE.match(host):
        raise Invalid("Indirizzo non valido: scrivi un indirizzo IP o un nome host, senza spazi.")
    try:
        netpolicy.check_host(host, settings.allowed_networks, settings.denied_hosts, resolve=False)
    except netpolicy.HostNotAllowed as e:
        raise Invalid(str(e)) from None
    if not _USER_RE.match(ssh_user):
        raise Invalid("Utente SSH non valido.")
    if not 1 <= port <= 65535:
        raise Invalid("La porta deve essere tra 1 e 65535.")
    if method not in ("password", "key"):
        raise Invalid("Scegli come accedere: password oppure chiave privata.")
    owner_id = target.created_by if not new else data.get("_owner_id")
    other = s.scalar(select(Target).where(func.lower(Target.name) == name.lower(), Target.created_by == owner_id))
    if other is not None and other.id != target.id:
        raise Invalid("Hai già un obiettivo con questo nome.")
    tags = parse_tags(data.get("tags", ""))
    method_changed = (not new) and method != target.auth_method
    if (new or method_changed) and not secret.strip():
        raise Invalid("Inserisci la password SSH." if method == "password" else "Incolla la chiave privata.")
    if secret.strip():
        if method == "key":
            check_private_key(secret)
            target.secret_enc = box.encrypt(secret.strip() + "\n")
        else:
            if len(secret) > 500:
                raise Invalid("Password troppo lunga.")
            target.secret_enc = box.encrypt(secret)
    if sudo_password:
        target.sudo_password_enc = box.encrypt(sudo_password)
    elif data.get("clear_sudo_password"):
        target.sudo_password_enc = ""
    # Se cambia la macchina a cui ci si collega, la chiave del server registrata non vale più.
    if not new and (host != target.host or port != target.port):
        target.host_key = ""
    target.name, target.host, target.port, target.ssh_user = name, host, port, ssh_user
    target.auth_method = method
    target.notes = str(data.get("notes", "") or "")[:2000]
    target.tags = tags


_TAG_RE = re.compile(r"^[a-z0-9àèéìòù][a-z0-9àèéìòù_.-]{0,29}$")
MAX_TAGS = 8


def parse_tags(raw) -> list[str]:
    """"Aula 3, linux,  server web" -> ["aula-3", "linux", "server-web"]."""
    items = raw if isinstance(raw, (list, tuple)) else str(raw or "").replace(";", ",").split(",")
    out: list[str] = []
    for item in items:
        tag = re.sub(r"\s+", "-", str(item).strip().lower())
        if not tag:
            continue
        if not _TAG_RE.match(tag):
            raise Invalid(f"Tag «{str(item).strip()[:30]}» non valido: usa lettere, numeri e trattini, al massimo 30 caratteri.")
        if tag not in out:
            out.append(tag)
    if len(out) > MAX_TAGS:
        raise Invalid(f"Al massimo {MAX_TAGS} tag per obiettivo.")
    return out


def all_tags(targets) -> list[str]:
    return sorted({tag for t in targets for tag in (t.tags or [])})


def target_to_dict(t: Target) -> dict:
    """Mai le credenziali: solo se sono impostate."""
    return {"id": t.id, "name": t.name, "host": t.host, "port": t.port, "ssh_user": t.ssh_user,
            "tags": list(t.tags or []), "owner": t.owner.username if t.owner else None,
            "auth_method": t.auth_method, "has_sudo_password": bool(t.sudo_password_enc),
            "host_key_known": bool(t.host_key), "notes": t.notes, "archived": t.archived,
            "created_at": iso(t.created_at)}


def host_key_fingerprint(host_key: str) -> str:
    """Impronta SHA256 come la mostra ssh-keygen ("" se non c'è la chiave)."""
    import base64
    import hashlib
    try:
        kind, b64 = host_key.split()[:2]
        digest = hashlib.sha256(base64.b64decode(b64)).digest()
        return f"{kind} SHA256:{base64.b64encode(digest).decode().rstrip('=')}"
    except Exception:
        return ""


# --------------------------------------------------------------------------- scansioni

def enqueue_scan(s: Session, target: Target, user: User | None, preset: str,
                 custom: list[str] | None = None, options: dict | None = None) -> Scan:
    """Mette in coda una scansione. Invalid se i dati non vanno bene o la coda è piena."""
    if target.archived:
        raise Invalid(f"L'obiettivo «{target.name}» è archiviato.")
    try:
        tools = eng.tools_for(preset, custom)
    except ValueError as e:
        raise Invalid(str(e)) from None
    queued = s.scalar(select(func.count()).select_from(Scan).where(
        Scan.target_id == target.id, Scan.status.in_(ACTIVE_STATES)))
    if queued >= MAX_QUEUED_PER_TARGET:
        raise Invalid(f"«{target.name}» ha già {queued} scansioni in coda o in corso: aspetta che finiscano.")
    opts = {k: True for k in OPTION_LABELS if (options or {}).get(k)}
    scan = Scan(target_id=target.id, requested_by=user.id if user else None, preset=preset,
                tools=tools, options=opts, status="queued", current_step="In coda")
    s.add(scan)
    s.flush()
    return scan


def request_cancel(s: Session, scan: Scan) -> bool:
    """Annulla subito se è in coda, chiede l'interruzione se è in corso. False se già finita."""
    from watchdog_web.models import now
    if scan.status == "queued":
        scan.status, scan.finished_at = "cancelled", now()
        scan.current_step, scan.error = "Annullata", "Annullata prima di iniziare."
        return True
    if scan.status == "running":
        scan.cancel_requested = True
        return True
    return False


def queue_position(s: Session, scan: Scan) -> int | None:
    if scan.status != "queued":
        return None
    return 1 + s.scalar(select(func.count()).select_from(Scan).where(Scan.status == "queued", Scan.id < scan.id))


def scan_to_dict(scan: Scan, *, log: bool = False) -> dict:
    d = {
        "id": scan.id, "target_id": scan.target_id, "target": scan.target.name if scan.target else None,
        "status": scan.status, "status_label": STATUS_LABEL.get(scan.status, scan.status),
        "preset": scan.preset, "tools": list(scan.tools or []), "options": dict(scan.options or {}),
        "progress": scan.progress, "current_step": scan.current_step,
        "cancel_requested": scan.cancel_requested,
        "created_at": iso(scan.created_at), "started_at": iso(scan.started_at),
        "finished_at": iso(scan.finished_at), "duration_seconds": scan.duration_seconds,
        "error": scan.error or None,
    }
    if scan.status == "done":
        d.update({"risk_level": scan.risk_level, "risk_score": scan.risk_score, "system": scan.system_label,
                  "counts": scan.counts, "areas": scan.areas,
                  # Controlli non completati: un risultato pulito NON è garantito finché non sono zero.
                  "incomplete_checks": scan.incomplete,
                  "incomplete_details": (scan.summary or {}).get("errors", [])})
    if log:
        d["log"] = scan.log
    return d


def finding_to_dict(f: Finding) -> dict:
    return {"id": f.id, "position": f.position, "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "risk": f.risk, "area": f.area, "category": f.category,
            "source": f.source, "description": f.description, "evidence": f.evidence,
            "recommendation": f.recommendation, "command": f.command or None, "references": f.refs or {}}


def latest_done(s: Session, target_ids: list[int] | None = None) -> dict[int, Scan]:
    """Ultima scansione completata di ogni obiettivo."""
    sub = select(Scan.target_id, func.max(Scan.id).label("mid")).where(Scan.status == "done").group_by(Scan.target_id)
    if target_ids is not None:
        sub = sub.where(Scan.target_id.in_(target_ids))
    sub = sub.subquery()
    rows = s.scalars(select(Scan).join(sub, Scan.id == sub.c.mid)).all()
    return {r.target_id: r for r in rows}


def compare_scans(s: Session, old: Scan, new: Scan) -> dict:
    """Cosa è cambiato tra due scansioni dello stesso obiettivo (INFO esclusi)."""
    def keyed(scan: Scan) -> dict:
        rows = s.scalars(select(Finding).where(Finding.scan_id == scan.id, Finding.severity != "INFO")).all()
        return {finding_key(f.source, f.title): f for f in rows}

    a, b = keyed(old), keyed(new)
    # Un problema sparito conta come "risolto" solo se il controllo che lo trovava è stato
    # rieseguito fino in fondo: altrimenti non si sa, e lo si dice.
    ran = set(new.tools or [])
    incomplete = set((new.summary or {}).get("incomplete_checks") or [])
    resolved, not_rechecked = [], []
    for k, f in a.items():
        if k in b:
            continue
        check = check_of(f.source)
        (resolved if check in ran and check not in incomplete else not_rechecked).append(f)
    order = lambda f: (SEVERITIES.index(f.severity), f.title)   # noqa: E731
    return {
        "new": sorted((f for k, f in b.items() if k not in a), key=order),
        "resolved": sorted(resolved, key=order),
        "not_rechecked": sorted(not_rechecked, key=order),
        "persistent": sorted((f for k, f in b.items() if k in a), key=order),
        "score_delta": (new.risk_score or 0) - (old.risk_score or 0),
    }


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- dati per i grafici

def score_history(s: Session, target_ids: list[int], limit: int = 12) -> dict[int, list[dict]]:
    """Rischio delle ultime scansioni completate di ogni obiettivo, dalla più vecchia alla più recente."""
    if not target_ids:
        return {}
    rows = s.execute(select(Scan.id, Scan.target_id, Scan.finished_at, Scan.risk_score, Scan.risk_level,
                            Scan.incomplete)
                     .where(Scan.target_id.in_(target_ids), Scan.status == "done")
                     .order_by(Scan.target_id, Scan.id.desc())).all()
    out: dict[int, list[dict]] = {}
    for r in rows:
        items = out.setdefault(r.target_id, [])
        if len(items) < limit:
            items.append({"scan_id": r.id, "at": r.finished_at, "score": int(r.risk_score or 0),
                          "level": r.risk_level, "incomplete": int(r.incomplete or 0)})
    for items in out.values():
        items.reverse()
    return out


def area_breakdown(s: Session, scan: Scan) -> dict[str, dict[str, int]]:
    """Per area, quanti problemi di ogni gravità (informazioni escluse)."""
    rows = s.execute(select(Finding.area, Finding.severity, func.count())
                     .where(Finding.scan_id == scan.id, Finding.severity != "INFO")
                     .group_by(Finding.area, Finding.severity)).all()
    out: dict[str, dict[str, int]] = {}
    for area, sev, n in rows:
        out.setdefault(area, {})[sev] = int(n)
    return out


_PORT_LINE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s*(.*)$")


def open_ports(s: Session, scan: Scan) -> dict:
    """Porte aperte trovate da Nmap in una scansione, lette dai suoi risultati.

    internal = vista dalla macchina stessa; external = raggiungibile dal computer di WatchDog.
    severity = gravità del problema legato a quella porta (servizio rischioso), se c'è.
    """
    rows = s.scalars(select(Finding).where(Finding.scan_id == scan.id,
                                           Finding.source.like("nmap%"))).all()
    ports: dict[tuple[int, str], dict] = {}
    ran = {"internal": False, "external": False}
    for f in rows:
        kind = "external" if f.source.startswith("nmap-external:") else "internal"
        tail = f.source.split(":", 1)[1] if ":" in f.source else ""
        if tail in ("open-ports", "summary", "none", "filtered", "extra") or tail.startswith("port-"):
            ran[kind] = True
        if tail == "open-ports":
            for line in (f.evidence or "").splitlines():
                m = _PORT_LINE.match(line)
                if m:
                    p = ports.setdefault((int(m.group(1)), m.group(2)), {
                        "port": int(m.group(1)), "proto": m.group(2), "service": m.group(3).strip()[:40],
                        "internal": False, "external": False, "severity": None, "risk": ""})
                    p[kind] = True
                    p["service"] = p["service"] or m.group(3).strip()[:40]
    for f in rows:
        tail = f.source.split(":", 1)[1] if ":" in f.source else ""
        if not tail.startswith("port-"):
            continue
        m = _PORT_LINE.match(f.evidence or "")
        port = int(m.group(1)) if m else int(tail[5:]) if tail[5:].isdigit() else None
        proto = m.group(2) if m else "tcp"
        if port is None:
            continue
        kind = "external" if f.source.startswith("nmap-external:") else "internal"
        p = ports.setdefault((port, proto), {"port": port, "proto": proto, "service": "", "internal": False,
                                             "external": False, "severity": None, "risk": ""})
        p[kind] = True
        if p["severity"] is None or SEVERITIES.index(f.severity) < SEVERITIES.index(p["severity"]):
            p["severity"], p["risk"] = f.severity, f.title
    return {"ports": sorted(ports.values(), key=lambda p: (p["port"], p["proto"])),
            "ran_internal": ran["internal"], "ran_external": ran["external"], "scan": scan}


def area_breakdowns(s: Session, scan_ids: list[int]) -> dict[int, dict[str, dict[str, int]]]:
    """Come area_breakdown, per più scansioni insieme (una query sola)."""
    if not scan_ids:
        return {}
    rows = s.execute(select(Finding.scan_id, Finding.area, Finding.severity, func.count())
                     .where(Finding.scan_id.in_(scan_ids), Finding.severity != "INFO")
                     .group_by(Finding.scan_id, Finding.area, Finding.severity)).all()
    out: dict[int, dict[str, dict[str, int]]] = {}
    for scan_id, area, sev, n in rows:
        out.setdefault(scan_id, {}).setdefault(area, {})[sev] = int(n)
    return out
