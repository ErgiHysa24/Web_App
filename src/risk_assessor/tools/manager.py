"""Coordinates execution of security tools, including lifecycle."""
from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field

from risk_assessor.executor import TIMEOUT_RC, BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.tools.base import SecurityTool, ToolState, find_tool
from risk_assessor.lifecycle.installation import (
    InstallationTracker, InstallState, ensure_tool_installed,
)
from risk_assessor.lifecycle.cleanup import run_cleanup, CleanupReport
from risk_assessor.lifecycle.package_manager import detect_package_manager, is_not_found

EPEL_PACKAGE = "epel-release"
EPEL_DOCS = "https://docs.fedoraproject.org/en-US/epel/"
_EPEL_CHECK = "rpm -q epel-release >/dev/null 2>&1 || ls /etc/yum.repos.d/epel*.repo >/dev/null 2>&1"

logger = logging.getLogger(__name__)


class _TimeoutWatch(BaseExecutor):
    """Inoltra i comandi all'executor reale e annota quelli interrotti per timeout.

    Serve a non presentare come "pulito" il risultato di un tool che non ha finito:
    i parser vedrebbero un output vuoto/parziale e direbbero "0 problemi".
    """

    def __init__(self, inner: BaseExecutor) -> None:
        self._inner = inner
        self.timed_out: list[str] = []

    def execute_command(self, command, stdin=None, timeout=None):
        kwargs = {} if timeout is None else {"timeout": timeout}
        out, err, rc = self._inner.execute_command(command, stdin=stdin, **kwargs)
        if rc == TIMEOUT_RC and (err or "").startswith("timeout:"):
            self.timed_out.append(f"{' '.join(command)[:120]} ({err.strip()})")
        return out, err, rc

    def get_remote_hostname(self):
        return self._inner.get_remote_hostname()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _timeout_finding(tool_name: str, details: list[str]) -> Finding:
    return Finding(
        title=f"{tool_name}: esecuzione interrotta per timeout",
        category="assessment",
        severity=Severity.INFO,
        description=(
            f"{tool_name} non ha terminato entro il tempo massimo: i suoi risultati "
            "sono INCOMPLETI. L'assenza di segnalazioni non significa che il "
            "sistema sia a posto."
        ),
        evidence="; ".join(details)[:500],
        recommendation=(
            "Rieseguire il tool separatamente o restringerne il perimetro "
            "(es. tools.clamav.scan_paths nel config)."
        ),
        source=f"{tool_name}:timeout",
        confidence=Confidence.LOW,
    )


@dataclass
class ToolRunReport:
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    installed_by_assessor: list[str] = field(default_factory=list)
    pre_existing: list[str] = field(default_factory=list)


class ToolManager:
    """Esegue una lista di SecurityTool, gestendo install/cleanup."""

    def __init__(
        self,
        tools: list[SecurityTool],
        allow_install: bool = False,
        keep_tools: bool = False,
        sudo_password: str | None = None,
        allow_epel: bool = False,
    ) -> None:
        self.tools = tools
        self.allow_install = allow_install
        self.keep_tools = keep_tools
        self.allow_epel = allow_epel
        self.tracker = InstallationTracker()
        self.errors: dict[str, str] = {}
        # Tool richiesti ma senza senso su questo target (piattaforma o distro): non sono
        # errori, ma il report li elenca, così nessuno li scambia per "tutto a posto".
        self.not_applicable: dict[str, str] = {}
        self._epel_state: str | None = None   # None = non verificato, "on", "off", "failed"
        self.results: dict[str, list[Finding]] = {}
        # Secondi per tool: {"install": ..., "run": ...}, e quanto è durata la pulizia.
        self.durations: dict[str, dict[str, float]] = {}
        self.cleanup_seconds: float = 0.0
        self.cleanup_report: CleanupReport | None = None
        # Sudo context
        from risk_assessor.lifecycle.sudo import SudoContext
        self.sudo_ctx = SudoContext(password=sudo_password)

    def run_all(self, executor: BaseExecutor, target: str | None = None, progress=None) -> list[Finding]:
        """Esegue detect + (install) + run + parse per ogni tool, poi il cleanup.

        Il cleanup e l'azzeramento della password sudo avvengono SEMPRE, anche se
        l'esecuzione viene interrotta (Ctrl+C) o va in errore: altrimenti i
        pacchetti installati dall'assessment resterebbero sul target.

        Mostra progress per ogni tool se `progress` è fornito.
        """
        try:
            return self._run_tools(executor, target, progress)
        finally:
            try:
                if not self.keep_tools:
                    started = time.monotonic()
                    self.cleanup_report = run_cleanup(
                        self.tracker, executor, sudo_ctx=self.sudo_ctx,
                    )
                    self.cleanup_seconds = round(time.monotonic() - started, 1)
            finally:
                self.sudo_ctx.clear()

    def _run_tools(self, executor: BaseExecutor, target: str | None, progress) -> list[Finding]:
        """Ciclo detect/install/run/parse (senza cleanup, gestito da run_all)."""
        all_findings: list[Finding] = []

        host = host_info(executor)

        for tool in self.tools:
            if progress is not None:
                progress.start_step(f"Tool: {tool.name}")
            started = time.monotonic()

            # ---- 0. il tool ha senso su questo sistema? ----
            reason = tool.unsupported_reason(host)
            if reason:
                self.not_applicable[tool.name] = reason
                if progress is not None:
                    progress.skip(reason)
                continue

            # ---- 1. detect ----
            try:
                installed = tool.detect(executor)
            except Exception as e:
                self.errors[tool.name] = f"detect failed: {e}"
                if progress is not None:
                    progress.fail(f"detect: {type(e).__name__}")
                continue

            # ---- 2. install se necessario ----
            if not installed:
                ok = self._install(tool, executor, host, progress)
                self.durations[tool.name] = {"install": round(time.monotonic() - started, 1)}
                if not ok:
                    continue
            else:
                pkgs = tool.packages_for(host) or ([tool.package] if tool.package else [tool.name])
                self.tracker.record(tool.name, " ".join(pkgs), InstallState.PRE_EXISTING)

            # ---- 3. run + parse ----
            # NON riconnettere per tool: sshd ha MaxStartups e rifiuta
            # troppe connessioni ravvicinate. Usa la stessa connessione.

            watch = _TimeoutWatch(executor)
            run_started = time.monotonic()
            try:
                raw = tool.run(watch, target=target)
            except Exception as e:
                self.errors[tool.name] = f"run failed: {type(e).__name__}: {e}"
                if progress is not None:
                    progress.fail(f"run: {type(e).__name__}")
                continue

            try:
                findings = tool.parse(raw)
            except Exception as e:
                self.errors[tool.name] = f"parse failed: {e}"
                if progress is not None:
                    progress.fail(f"parse: {type(e).__name__}")
                continue

            if watch.timed_out:
                # Le segnalazioni trovate prima dell'interruzione restano valide;
                # i riepiloghi ("0 warning", "nessuna infezione") no.
                findings = [f for f in findings if not f.source.endswith(":summary")]
                findings.append(_timeout_finding(tool.name, watch.timed_out))
                self.errors[tool.name] = "timeout"

            self.durations.setdefault(tool.name, {})["run"] = round(time.monotonic() - run_started, 1)
            self.results[tool.name] = findings
            all_findings.extend(findings)
            if progress is not None:
                if watch.timed_out:
                    progress.fail("timeout: risultati incompleti")
                else:
                    progress.ok(f"({len(findings)} finding)")

        return all_findings

    def _install(self, tool: SecurityTool, executor: BaseExecutor, host: HostInfo, progress) -> bool:
        """Installa un tool assente. False (con il motivo registrato) se non si può."""
        def stop(message: str, *, applicable: bool = True) -> bool:
            if applicable:
                self.errors[tool.name] = message
            else:
                self.not_applicable[tool.name] = message
            if progress is not None:
                progress.skip(message)
            return False

        if not self.allow_install:
            return stop("non installato (installazione disattivata)")

        pkgs: list[str] | None = None
        state = tool.install_custom(executor, self.tracker, self.sudo_ctx)
        if state is None:
            pkgs = tool.packages_for(host)
            if not pkgs:
                return stop(tool.unavailable_message(host), applicable=False)
            if tool.needs_epel(host):
                problem = self._ensure_epel(executor)
                if problem:
                    return stop(problem)
            state = ensure_tool_installed(
                self.tracker, tool.name, " ".join(pkgs), executor, allow_install=True,
                sudo_ctx=self.sudo_ctx,
            )

        if state == InstallState.INSTALLED_BY_ASSESSOR:
            tool.state = ToolState.INSTALLED_BY_ASSESSOR
            resolved = find_tool(executor, tool.name)
            if resolved:
                tool._path = resolved
            # Componenti extra (es. contenuto SCAP per OpenSCAP). Un errore
            # qui non deve bloccare il tool: i suoi marker lo segnaleranno.
            try:
                tool.post_install(executor, self.tracker, self.sudo_ctx)
            except Exception as e:
                logger.warning("post-install di %s fallito: %s", tool.name, e)
            return True
        if state == InstallState.PRE_EXISTING:
            tool.state = ToolState.PRE_EXISTING
            resolved = find_tool(executor, tool.name)
            if resolved:
                tool._path = resolved
            return True
        if state == InstallState.UNKNOWN:
            message = "installazione non possibile: gestore dei pacchetti non riconosciuto"
        elif pkgs:
            rec = self.tracker.get(tool.name)
            if rec is not None and is_not_found(rec.error):
                # Il pacchetto non esiste per questa versione (es. rkhunter su Tumbleweed):
                # non è un controllo fallito, è un tool che qui non c'è.
                return stop(f"{tool.unavailable_message(host)} ({rec.error})", applicable=False)
            message = f"installazione di {' '.join(pkgs)} non riuscita"
            if rec is not None and rec.error:
                message += f" ({rec.error})"
        else:
            message = "install failed"
        self.errors[tool.name] = message
        if progress is not None:
            progress.fail(message)
        return False

    def _ensure_epel(self, executor: BaseExecutor) -> str | None:
        """Rende disponibile EPEL (RHEL e derivate). Ritorna il problema, o None se è attivo."""
        if self._epel_state is None:
            _, _, rc = executor.execute_command(["sh", "-c", _EPEL_CHECK])
            self._epel_state = "on" if rc == 0 else "off"
        if self._epel_state == "on":
            return None
        if self._epel_state == "failed":
            return self._epel_failed()
        if not self.allow_epel:
            return ("richiede il repository EPEL, non attivo sul target: "
                    "abilitalo con --enable-epel o dal menu Impostazioni")
        pm = detect_package_manager(executor)
        ok, error = (pm.install_result(executor, EPEL_PACKAGE, sudo_ctx=self.sudo_ctx)
                     if pm is not None else (False, "gestore dei pacchetti non riconosciuto"))
        if ok:
            # Registrato come gli altri pacchetti: la pulizia lo rimuove alla fine.
            self.tracker.record("epel", EPEL_PACKAGE, InstallState.INSTALLED_BY_ASSESSOR)
            self._epel_state = "on"
            return None
        self._epel_state = "failed"
        self._epel_error = error
        return self._epel_failed()

    def _epel_failed(self) -> str:
        why = f": {self._epel_error}" if getattr(self, "_epel_error", "") else ""
        return f"richiede il repository EPEL, che non è stato possibile attivare{why} ({EPEL_DOCS})"

    def get_state(self, tool_name: str) -> ToolState:
        for t in self.tools:
            if t.name == tool_name:
                return t.state
        return ToolState.UNKNOWN

    def get_tracker_states(self) -> dict[str, InstallState]:
        return {name: rec.state for name, rec in self.tracker.records.items()}
