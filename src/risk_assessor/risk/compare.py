"""Confronto tra due assessment dello stesso target.

Un finding è "lo stesso" se ha la stessa origine (`source`) e lo stesso titolo. Contano
solo i problemi: i finding informativi (INFO) non entrano in nuovi/risolti/invariati.

Il precedente si sceglie in due modi: automaticamente (l'assessment.json più recente
dello stesso target nella cartella dei report, `find_previous`) oppure indicandolo con
`--compare FILE` (`load_assessment`). Entrambi non sollevano mai eccezioni: senza
precedente leggibile il report semplicemente non mostra il confronto.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from risk_assessor.models import Assessment, Finding, Severity
from risk_assessor.sanitize import clean_text

MAX_PREVIOUS_BYTES = 20 * 1024 * 1024
_MAX_DIRS_SCANNED = 300
_SEVERITIES = {s.value for s in Severity}


# Solo i numeri "isolati" (conteggi, percentuali): quelli attaccati a un nome fanno parte
# dell'identità del problema (libssl3, python3.12, net.ipv4) e restano com'è.
_NUMBER = re.compile(r"(?<![A-Za-z0-9_.@/-])\d+(?:[.,]\d+)*(?![A-Za-z_])")


def finding_key(source, title) -> tuple[str, str]:
    """Chiave con cui due finding di scansioni diverse sono "lo stesso problema".

    I numeri nel titolo (conteggi, percentuali, versioni: "File SUID trovati: 10",
    "Disco quasi pieno: /opt (93%)") cambiano da una scansione all'altra senza che il
    problema sia nuovo o risolto: nella chiave vengono neutralizzati. L'origine resta
    com'è, e porta già l'identificatore quando serve (porta, pacchetto, parametro).
    """
    return (clean_text(str(source)), _NUMBER.sub("#", clean_text(str(title))))


def load_assessment(path: Path) -> dict | None:
    """Contenuto di un assessment.json (o della cartella che lo contiene), o None se non valido."""
    try:
        p = Path(path)
        if p.is_dir():
            p = p / "assessment.json"
        if not p.is_file() or p.stat().st_size > MAX_PREVIOUS_BYTES:
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        datetime.fromisoformat(str(data["started_at"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    return data


_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._@-]")
_MAX_TARGET_IN_NAME = 80


def report_dir_prefix(target: str) -> str:
    """Inizio del nome delle cartelle dei report di un obiettivo: server-<target>-.

    Solo caratteri sicuri in ogni file system (anche Windows); un obiettivo molto lungo
    viene accorciato e completato con un hash breve, così il nome resta sotto il limite
    di 255 byte e due obiettivi diversi non finiscono nella stessa cartella.
    """
    safe = _SAFE_CHARS.sub("_", target).strip("._") or "target"
    if len(safe) > _MAX_TARGET_IN_NAME or safe != target.replace("/", "_").replace(":", "_"):
        import hashlib
        digest = hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:8]
        safe = f"{safe[:_MAX_TARGET_IN_NAME]}-{digest}"
    return f"server-{safe}-"


def find_previous(base_dir: Path, target: str, started_at: datetime) -> dict | None:
    """L'assessment.json più recente dello stesso target in `base_dir`, precedente a `started_at`.

    Guarda solo le cartelle il cui nome è quello dell'obiettivo (non tutte quelle in
    `base_dir`), dalla più recente: con tanti report e tanti host resta veloce e non
    perde l'obiettivo giusto.
    """
    prefix = report_dir_prefix(target)
    try:
        dirs = [d for d in Path(base_dir).iterdir() if d.is_dir() and d.name.startswith(prefix)]
    except OSError:
        return None

    def mtime(d: Path) -> float:
        try:
            return d.stat().st_mtime
        except OSError:
            return 0.0
    best: tuple[datetime, dict] | None = None
    for d in sorted(dirs, key=mtime, reverse=True)[:_MAX_DIRS_SCANNED]:
        data = load_assessment(d / "assessment.json")
        if data is None or clean_text(str(data.get("target", ""))) != target:
            continue
        when = datetime.fromisoformat(str(data["started_at"]))
        if when.tzinfo is None:
            when = when.replace(tzinfo=started_at.tzinfo)
        try:
            if when >= started_at:
                continue
        except TypeError:
            continue
        if best is None or when > best[0]:
            best = (when, data)
    return best[1] if best else None


# Prefisso della source -> nome del controllo (come in --tools), per sapere se un finding
# della scansione precedente è stato ricontrollato.
_CHECK_BY_PREFIX = {"linux-check": "linux", "users-collector": "users", "ssh-config": "ssh_config",
                    "auth-policy": "auth_policy", "nmap-external": "nmap_external", "polyscan": "polyscan"}
_MACOS_CHECK = [("macos:uid0", "users"), ("macos:admins", "users"), ("macos:root", "users"),
                ("macos:guest", "users"), ("macos:autologin", "users"), ("macos:ssh", "ssh_config"),
                ("macos:firewall", "firewall"), ("macos:stealth", "firewall"), ("macos:sharing", "services"),
                ("macos:password-policy", "auth_policy"), ("macos:updates", "updates"),
                ("macos:auto-", "updates"), ("macos:security-updates", "updates"),
                ("macos:launch", "persistence"), ("macos:sip", "protections"),
                ("macos:filevault", "protections"), ("macos:gatekeeper", "protections"),
                ("macos:system", "linux")]


def check_of(source: str) -> str:
    """Nome del controllo (come in --tools) che produce un finding con questa source."""
    source = (source or "").lower()
    if source.startswith("macos:"):
        return next((c for p, c in _MACOS_CHECK if source.startswith(p)), "")
    prefix = source.split(":", 1)[0]
    return _CHECK_BY_PREFIX.get(prefix, prefix.replace("-", "_"))


_INCOMPLETE_SUFFIXES = ("unverifiable", "unreadable", "unknown", "failed", "error", "sudo-required",
                        "partial", "timeout")


def incomplete_checks(a: Assessment) -> set[str]:
    """Controlli che in questa scansione non hanno lavorato del tutto (errori, non verificabili,
    non applicabili): i loro problemi precedenti non possono dirsi risolti."""
    checks = {e.split(":", 1)[0].strip().lower() for e in a.errors if ":" in e}
    checks |= set(a.not_applicable())
    for f in a.findings:
        if f.source.rsplit(":", 1)[-1].lower().endswith(_INCOMPLETE_SUFFIXES):
            checks.add(check_of(f.source))
    return {c for c in checks if c}


@dataclass
class Comparison:
    previous_target: str
    previous_date: str                       # già formattata per i report
    previous_score: int | None
    current_score: int
    new: list[Finding] = field(default_factory=list)
    resolved: list[tuple[str, str, str]] = field(default_factory=list)   # (severità, titolo, source)
    unchanged: int = 0
    # Problemi della scansione precedente il cui controllo questa volta non è stato eseguito:
    # non sono "risolti", semplicemente non si sa.
    not_rechecked: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def delta(self) -> int | None:
        return None if self.previous_score is None else self.current_score - self.previous_score

    @property
    def trend(self) -> str:
        d = self.delta
        if d is None or d == 0:
            return "invariato"
        return "peggiorato" if d > 0 else "migliorato"

    def new_keys(self) -> set[tuple[str, str]]:
        return {finding_key(f.source, f.title) for f in self.new}

    def to_dict(self) -> dict:
        return {
            "previous_target": self.previous_target,
            "previous_date": self.previous_date,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "delta": self.delta,
            "trend": self.trend,
            "new": [{"severity": f.severity.value, "title": f.title, "source": f.source} for f in self.new],
            "resolved": [{"severity": s, "title": t, "source": src} for s, t, src in self.resolved],
            "unchanged": self.unchanged,
            "not_rechecked": [{"severity": s, "title": t, "source": src} for s, t, src in self.not_rechecked],
        }


def compare(current: Assessment, previous: dict | None) -> Comparison | None:
    """Confronta l'assessment corrente con il contenuto di un assessment.json precedente."""
    if not previous or not isinstance(previous.get("findings"), list):
        return None
    prev_items = []
    for d in previous["findings"]:
        if not isinstance(d, dict):
            continue
        sev = str(d.get("severity", "INFO"))
        if sev not in _SEVERITIES:
            sev = "INFO"
        key = finding_key(d.get("source", ""), d.get("title", ""))
        prev_items.append((key, sev))
    prev_keys = {k for k, _ in prev_items}
    cur_keys = {finding_key(f.source, f.title) for f in current.findings}
    problems = [f for f in current.findings if f.severity != Severity.INFO]
    new = [f for f in problems if finding_key(f.source, f.title) not in prev_keys]
    incomplete = incomplete_checks(current)
    ran_now = {t for t in current.tools_used if t != "all"}
    resolved, not_rechecked, seen = [], [], set()
    for key, sev in prev_items:
        if sev != "INFO" and key not in cur_keys and key not in seen:
            seen.add(key)
            check = check_of(key[0])
            # Risolto solo se il suo controllo è stato rieseguito ed è andato a buon fine.
            skipped = bool(ran_now) and "all" not in current.tools_used and check not in ran_now
            target = not_rechecked if skipped or check in incomplete else resolved
            target.append((sev, key[1], key[0]))
    unchanged = sum(1 for f in problems if finding_key(f.source, f.title) in prev_keys)

    risk = previous.get("risk") if isinstance(previous.get("risk"), dict) else {}
    try:
        prev_score = max(0, min(100, int(risk.get("score"))))
    except (TypeError, ValueError):
        prev_score = None
    when = clean_text(str(previous.get("started_at", "")))
    try:
        when = datetime.fromisoformat(when).strftime("%d/%m/%Y %H:%M UTC")
    except ValueError:
        pass
    order = [s.value for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)]
    resolved.sort(key=lambda r: (order.index(r[0]), r[1]))
    not_rechecked.sort(key=lambda r: (order.index(r[0]), r[1]))
    new.sort(key=lambda f: (order.index(f.severity.value), f.title))
    return Comparison(previous_target=clean_text(str(previous.get("target", ""))), previous_date=when,
                      previous_score=prev_score, current_score=int(current.risk_score),
                      new=new, resolved=resolved, unchanged=unchanged, not_rechecked=not_rechecked)


def assessment_from_dict(data: dict) -> Assessment:
    """Ricostruisce un Assessment (solo ciò che serve al confronto) da un assessment.json."""
    from risk_assessor.models import Confidence

    a = Assessment(target=str(data.get("target", "")), mode=str(data.get("mode", "")))
    try:
        a.started_at = datetime.fromisoformat(str(data["started_at"]))
    except (KeyError, ValueError):
        pass
    for d in data.get("findings") or []:
        if not isinstance(d, dict):
            continue
        sev = str(d.get("severity", "INFO"))
        conf = str(d.get("confidence", "MEDIUM"))
        a.add_finding(Finding(
            title=str(d.get("title", "")), category=str(d.get("category", "")),
            severity=Severity(sev) if sev in _SEVERITIES else Severity.INFO,
            description=str(d.get("description", "")), evidence=str(d.get("evidence", "")),
            recommendation=str(d.get("recommendation", "")), source=str(d.get("source", "")),
            confidence=Confidence(conf) if conf in {c.value for c in Confidence} else Confidence.MEDIUM))
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    try:
        a.risk_score = max(0, min(100, int(risk.get("score"))))
    except (TypeError, ValueError):
        a.risk_score = 0
    a.risk_level = str(risk.get("level", "LOW"))
    a.tools_used = [str(t) for t in data.get("tools_used") or [] if isinstance(t, str)]
    return a
