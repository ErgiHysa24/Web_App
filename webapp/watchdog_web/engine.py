"""Collegamento col motore di WatchDog: esegue una scansione presa dalla coda.

La web app non reimplementa nulla: apre la connessione SSH, chiama il motore
(`risk_assessor`) con un "progress" che scrive l'avanzamento nel database, poi salva
report e finding. L'annullamento è cooperativo: tra un passo e l'altro il motore chiede
l'avanzamento, lì si controlla la richiesta e si interrompe come farebbe Ctrl+C, così i
tool installati vengono comunque rimossi dal sistema analizzato.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from risk_assessor import cli as wd
from risk_assessor.config import load_config
from risk_assessor.executor import SSHConnectionError, SSHExecutor
from risk_assessor.external_scan import valid_external_host
from risk_assessor.models import Assessment, Severity
from risk_assessor.risk.areas import AREAS, area_of
from risk_assessor.risk.attack import techniques_for
from risk_assessor.risk.compare import incomplete_checks
from risk_assessor.risk.compliance import controls_for
from risk_assessor.sanitize import clean_text

from watchdog_web import netpolicy
from watchdog_web.config import Settings
from watchdog_web.db import session_scope
from watchdog_web.models import Finding, Scan, now
from watchdog_web.security import SecretBox

_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_LOG_MAX = 20000

NATIVE_CHECKS = [name for name, _ in wd._COLLECTOR_FACTORIES]
EXTERNAL_TOOLS = [name for name, _ in wd._TOOL_FACTORIES]
OPTIONAL_TOOLS = [item[0] for item in wd.OPTIONAL_TOOLS]
TOOL_NOTES = {item[0]: item[2] for item in wd.OPTIONAL_TOOLS}

# id -> (nome, descrizione)
PRESETS = {
    "native": ("Controlli nativi", "Solo lettura, nessuna installazione sul sistema: circa un minuto."),
    "full": ("Completa", "Controlli nativi più i tool esterni (Nmap, Lynis, ClamAV…), installati e poi rimossi."),
    "custom": ("Personalizzata", "Scegli i singoli controlli e tool."),
}


class ScanCancelled(BaseException):
    """Annullamento richiesto dall'utente (BaseException come KeyboardInterrupt: il motore
    non la intercetta come errore di un controllo e fa comunque la pulizia)."""


def tools_for(preset: str, custom: list[str] | None = None) -> list[str]:
    """Elenco di controlli e tool per un tipo di scansione. ValueError se non valido."""
    cfg = load_config("/nonexistent/watchdog-config.yaml")     # sempre le impostazioni predefinite del motore
    if preset == "native":
        return list(NATIVE_CHECKS)
    if preset == "full":
        return wd._expand_tools(["all"], cfg, ())
    if preset == "custom":
        chosen = [t for t in (custom or []) if t]
        unknown = wd._unknown_tools(chosen)
        if unknown or not chosen:
            raise ValueError("Scegli almeno un controllo valido"
                             + (f" (sconosciuti: {', '.join(unknown)})" if unknown else "") + ".")
        ordered = [t for t in NATIVE_CHECKS + EXTERNAL_TOOLS if t in chosen]
        return ordered + [t for t in chosen if t not in ordered]
    raise ValueError("Tipo di scansione non valido.")


class DbProgress:
    """L'interfaccia di avanzamento del motore, scritta nel database."""

    def __init__(self, factory: sessionmaker[Session], scan_id: int) -> None:
        self.factory = factory
        self.scan_id = scan_id
        self.total = 0          # impostato dal motore
        self.done = 0
        self._label = ""

    def _update(self, line: str | None = None, step: str | None = None) -> None:
        with session_scope(self.factory) as s:
            scan = s.get(Scan, self.scan_id)
            if scan is None:
                raise ScanCancelled("scansione eliminata")
            scan.heartbeat_at = now()
            if step is not None:
                scan.current_step = step[:200]
                scan.progress = min(99, int(100 * self.done / self.total)) if self.total else 0
            if line:
                scan.log = (scan.log + clean_text(line) + "\n")[-_LOG_MAX:]
            cancel = scan.cancel_requested
        if cancel and step is not None:
            raise ScanCancelled("annullata dall'utente")

    # --- interfaccia usata dal motore (vedi risk_assessor.reports.progress) ---
    def banner(self, text: str) -> None:
        self._update(line=text)

    def blank(self) -> None:
        return None

    def start_step(self, label: str) -> None:
        self._label = label
        self._update(step=label)
        self.done += 1

    def ok(self, extra: str = "") -> None:
        self._update(line=f"OK    {self._label} {extra}".rstrip())

    def fail(self, reason: str = "") -> None:
        self._update(line=f"ERRORE {self._label}: {reason}".rstrip())

    def skip(self, reason: str = "") -> None:
        self._update(line=f"SALTATO {self._label}: {reason}".rstrip())

    def info(self, text: str) -> None:
        self._update(line=f"      {text}")


def _write_key(private_key: str) -> str:
    """Chiave privata in un file temporaneo leggibile solo dal processo (serve a Paramiko)."""
    fd, path = tempfile.mkstemp(prefix="wd-key-")
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        os.write(fd, (private_key.strip() + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return path


def area_summary(a: Assessment) -> dict:
    """Heatmap della scansione: per area, numero di problemi e severità peggiore."""
    areas: dict[str, dict] = {}
    for f in a.findings:
        if f.severity == Severity.INFO:
            continue
        cell = areas.setdefault(area_of(f), {"count": 0, "worst": "LOW"})
        cell["count"] += 1
        if _SEVS.index(f.severity.value) < _SEVS.index(cell["worst"]):
            cell["worst"] = f.severity.value
    return areas


def store_result(s: Session, scan: Scan, a: Assessment, report_dir: Path | None) -> None:
    """Salva l'esito di una scansione: riepilogo sulla riga della scansione e una riga per finding."""
    order = sorted(a.findings, key=lambda f: (_SEVS.index(f.severity.value), f.title))
    scan.risk_level = a.risk_level
    scan.risk_score = int(a.risk_score)
    scan.system_label = a.system_label()[:200]
    scan.counts = a.counts_by_severity()
    scan.areas = area_summary(a)
    scan.incomplete = len(a.errors)
    scan.report_dir = str(report_dir) if report_dir else ""
    scan.summary = {
        "errors": [clean_text(e)[:500] for e in a.errors][:100],
        "not_applicable": a.not_applicable(),
        "comparison": a.metadata.get("comparison"),
        "durations": a.metadata.get("durations"),
        "tools_used": list(a.tools_used),
        "cleanup": a.cleanup_status,
        "host": a.metadata.get("host"),
        "incomplete_checks": sorted(incomplete_checks(a)),
    }
    scan.findings.clear()
    for i, f in enumerate(order, 1):
        refs = {k: list(v) for k, v in controls_for(f).items()}
        techs = list(techniques_for(f))
        if techs:
            refs["attack"] = techs
        scan.findings.append(Finding(
            position=i, title=f.title[:500], severity=f.severity.value, confidence=f.confidence.value,
            risk=f.risk, area=area_of(f), category=f.category[:64], source=f.source[:200],
            description=f.description, evidence=f.evidence, recommendation=f.recommendation,
            command=f.command or "", refs=refs))


def run_scan(scan_id: int, factory: sessionmaker[Session], settings: Settings, box: SecretBox) -> None:
    """Esegue una scansione già marcata "running". Non solleva mai: l'esito finisce nel database."""
    key_path: str | None = None
    try:
        with session_scope(factory) as s:
            scan = s.get(Scan, scan_id)
            t = scan.target
            spec = {
                "host": t.host, "port": t.port, "user": t.ssh_user, "method": t.auth_method,
                "secret": box.decrypt(t.secret_enc), "sudo": box.decrypt(t.sudo_password_enc),
                "host_key": t.host_key, "tools": list(scan.tools), "options": dict(scan.options or {}),
                "target_id": t.id,
            }
        opts = spec["options"]
        progress = DbProgress(factory, scan_id)
        password = spec["secret"] if spec["method"] == "password" else None
        if spec["method"] == "key":
            key_path = _write_key(spec["secret"])
        # Senza password di sudo dedicata si prova quella SSH (di solito è la stessa dell'utente).
        sudo_password = spec["sudo"] or password

        progress.start_step("Connessione SSH")
        # Il nome si risolve adesso e ci si collega proprio all'indirizzo controllato.
        try:
            addresses = netpolicy.check_host(spec["host"], settings.allowed_networks, settings.denied_hosts,
                                             resolve=True)
        except netpolicy.HostNotAllowed as e:
            raise RuntimeError(f"Obiettivo non consentito: {e}") from None
        address = addresses[0]
        ex = SSHExecutor(host=address, user=spec["user"], port=spec["port"], key_file=key_path,
                         password=password, known_host_key=spec["host_key"] or None,
                         accept_new_host_key=not spec["host_key"])
        try:
            ex.connect()
        except SSHConnectionError as e:
            ex.close()
            reason = str(e)
            if spec["host_key"] and "BadHostKey" in reason:
                reason = ("la chiave del server è diversa da quella registrata alla prima connessione: "
                          "il server è stato reinstallato, oppure qualcuno si sta mettendo in mezzo. "
                          "Se il cambio è previsto, azzera la chiave nella scheda dell'obiettivo. " + reason)
            raise RuntimeError(f"Connessione SSH non riuscita: {reason}") from None
        progress.ok()
        if not spec["host_key"] and ex.server_host_key:
            with session_scope(factory) as s:
                s.get(Scan, scan_id).target.host_key = ex.server_host_key
        try:
            external = address if opts.get("external_scan") and valid_external_host(address) else None
            a = wd._run_assessment_core(
                ex, f"{spec['host']}:{spec['port']}", "ssh", spec["tools"],
                bool(opts.get("keep_tools")), False, sudo_password or None, bool(opts.get("no_install")),
                progress=progress, clamav_paths=None, external_host=external,
                allow_epel=bool(opts.get("allow_epel")))
        finally:
            ex.close()
        with session_scope(factory) as s:
            a.metadata["name"] = s.get(Scan, scan_id).target.name
        written = wd._write_reports(a, settings.reports_dir, ["json", "md", "html"])
        report_dir = written[0].parent if written else None
        with session_scope(factory) as s:
            scan = s.get(Scan, scan_id)
            store_result(s, scan, a, report_dir)
            scan.status, scan.progress, scan.current_step = "done", 100, "Completata"
            scan.finished_at = now()
    except ScanCancelled as e:
        _finish(factory, scan_id, "cancelled", f"Scansione annullata ({e}). I tool installati sono stati rimossi.")
    except Exception as e:      # qualsiasi errore diventa l'esito della scansione, mai un crash del worker
        _finish(factory, scan_id, "failed", clean_text(f"{type(e).__name__}: {e}")[:2000]
                if not isinstance(e, RuntimeError) else clean_text(str(e))[:2000])
    finally:
        if key_path:
            try:
                os.unlink(key_path)
            except OSError:
                pass


def _finish(factory: sessionmaker[Session], scan_id: int, status: str, message: str) -> None:
    with session_scope(factory) as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            return
        scan.status, scan.error, scan.finished_at = status, message, now()
        scan.current_step = "Annullata" if status == "cancelled" else "Non riuscita"
        scan.log = (scan.log + message + "\n")[-_LOG_MAX:]


__all__ = ["AREAS", "PRESETS", "NATIVE_CHECKS", "EXTERNAL_TOOLS", "OPTIONAL_TOOLS", "DbProgress",
           "ScanCancelled", "run_scan", "store_result", "tools_for"]
