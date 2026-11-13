"""ClamAV integration.

Configurabile con path mirati (default: /etc /tmp /var/tmp) per non
scansionare l'intero filesystem.
"""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import privileged_prefix
from risk_assessor.models import Finding
from risk_assessor.parsers.clamav import parse_clamav
from risk_assessor.tools.base import SecurityTool


DEFAULT_SCAN_PATHS = ["/etc", "/tmp", "/var/tmp"]

# Limiti di tempo: la scansione mirata è breve, quella completa può durare ore.
TARGETED_SCAN_TIMEOUT = 1800
FULL_SCAN_TIMEOUT = 6 * 3600
FRESHCLAM_TIMEOUT = 600

# Marcatore con cui run() segnala che clamscan non ha completato la scansione.
FAILED_MARKER = "__CLAMAV_FAILED__"
PARTIAL_MARKER = "__CLAMAV_PARTIAL__"
_DB_MISSING = "No supported database files found"


class ClamAVTool(SecurityTool):
    name = "clamscan"  # binario si chiama clamscan, pacchetto clamav
    package = "clamav"
    # freshclam (aggiornamento delle firme) è un pacchetto a parte su Fedora, RHEL e Alpine.
    packages = {"debian": ["clamav"], "fedora": ["clamav", "clamav-freshclam"],
                "rhel": ["clamav", "clamav-freshclam"], "suse": ["clamav"], "arch": ["clamav"],
                "alpine": ["clamav-scanner", "freshclam"],
                # macOS: solo se già installato. Con Homebrew freshclam va configurato a mano e il
                # database (centinaia di MB) resterebbe sul disco dopo la rimozione.
                "macos": None}
    epel_families = frozenset({"rhel"})
    platforms = frozenset({"linux", "darwin"})

    def __init__(
        self,
        scan_paths: list[str] | None = None,
        full_system_scan: bool = False,
        timeout: int | None = None,
    ) -> None:
        super().__init__()
        self.scan_paths = scan_paths or list(DEFAULT_SCAN_PATHS)
        self.full_system_scan = full_system_scan
        self._timeout = timeout

    @property
    def timeout(self) -> int:
        """Timeout effettivo: esplicito, oppure in base al tipo di scansione."""
        if self._timeout:
            return self._timeout
        return FULL_SCAN_TIMEOUT if self.full_system_scan else TARGETED_SCAN_TIMEOUT

    def detect(self, executor: BaseExecutor) -> bool:
        # il binario è "clamscan", non "clamav"
        from risk_assessor.tools.base import find_tool, ToolState
        path = find_tool(executor, "clamscan")
        if path:
            self._path = path
            self.state = ToolState.PRE_EXISTING
            return True
        self.state = ToolState.ABSENT
        return False

    def unavailable_message(self, host) -> str:
        if host.is_macos:
            return ("su macOS si usa solo se già installato (brew install clamav e configurazione "
                    "di freshclam)")
        return super().unavailable_message(host)

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        paths = ["/"] if self.full_system_scan else self.scan_paths
        # Niente --no-summary: così una scansione riuscita stampa sempre il
        # riepilogo e si distingue da una fallita (con -i una scansione pulita
        # senza riepilogo non produrrebbe alcun output).
        # Con i privilegi (root o sudo -n) clamscan legge anche i file protetti.
        prefix = privileged_prefix(executor)
        cmd = prefix + [self._path, "-r", "-i"] + paths
        out, err, rc = executor.execute_command(cmd, timeout=self.timeout)
        if rc == 2 and _DB_MISSING in (out or "") + (err or ""):
            # Database delle firme assente: primo aggiornamento, poi un solo nuovo tentativo.
            executor.execute_command(prefix + ["freshclam"], timeout=FRESHCLAM_TIMEOUT)
            out, err, rc = executor.execute_command(cmd, timeout=self.timeout)
        out = out or ""
        found = " FOUND" in out
        if rc not in (0, 1) and not found and "Infected files:" not in out:
            # Nessun riepilogo e nessuna infezione: la scansione non è avvenuta.
            # (Se ci sono righe FOUND, per esempio prima di un timeout, si conservano.)
            return f"{FAILED_MARKER} rc={rc}\n{(err or out or '').strip()}"
        result = out + "\n" + (err or "")
        if rc == 2:
            # Scansione arrivata in fondo ma con errori (tipicamente file non leggibili).
            result += f"\n{PARTIAL_MARKER}\n{(err or '').strip()[:300]}"
        return result

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_clamav(raw_output)
