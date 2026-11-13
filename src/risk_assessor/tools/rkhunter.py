"""rkhunter integration.

rkhunter richiede root per:
- Scrivere la baseline in /var/lib/rkhunter/ (`--propupd`)
- Leggere file di sistema protetti durante il check

Usa `sudo -n` (NOPASSWD). Se non disponibile, ritorna marker esplicito.
"""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import privileges
from risk_assessor.models import Finding
from risk_assessor.parsers.rkhunter import parse_rkhunter, BASELINE_CREATED_MARKER, FAILED_MARKER
from risk_assessor.tools.base import SecurityTool, ToolState, track_new_files

# Database delle proprietà dei file: è la baseline contro cui rkhunter confronta
BASELINE_DB = "/var/lib/rkhunter/db/rkhunter.dat"
# File che rkhunter crea alla prima esecuzione (baseline e log).
CREATED_FILES = [BASELINE_DB, "/var/log/rkhunter.log", "/var/log/rkhunter.log.old"]


class RkhunterTool(SecurityTool):
    name = "rkhunter"
    package = "rkhunter"
    packages = {"debian": ["rkhunter"], "fedora": ["rkhunter"], "rhel": ["rkhunter"],
                "suse": ["rkhunter"], "arch": ["rkhunter"], "alpine": None}
    epel_families = frozenset({"rhel"})

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # rkhunter richiede root
        priv = privileges(executor)
        if priv is None:
            return "__SUDO_REQUIRED__"

        # 1. Baseline: la creiamo SOLO se manca. Rilanciare --propupd prima di ogni
        #    check riscriverebbe la baseline con lo stato attuale (anche se già
        #    compromesso) e il confronto non potrebbe più rilevare nulla.
        _, _, rc_db = executor.execute_command(priv + ["test", "-s", BASELINE_DB])
        # Su un rkhunter dell'amministratore senza baseline non la si crea: resterebbe sul
        # sistema e le scansioni successive confronterebbero con una foto dell'assessment.
        baseline_created = rc_db != 0 and self.state != ToolState.PRE_EXISTING
        if baseline_created:
            executor.execute_command(priv + [self._path, "--propupd", "--nocolors"])

        # 2. Check
        cmd = priv + [self._path, "--check", "--skip-keypress",
               "--report-warnings-only", "--nocolors"]
        out, err, rc = executor.execute_command(cmd)
        out = out or ""
        # rc 0: nessun avviso, 1: avvisi trovati. Altro: il controllo non è andato a buon fine
        # (e con --report-warnings-only un errore produrrebbe un output vuoto = "0 warning").
        if rc not in (0, 1):
            return f"{FAILED_MARKER}\nrc={rc} {(err or out).strip()[:300]}"
        # rc 1 vuol dire "avvisi trovati", ma è anche l'uscita di rkhunter quando la sua
        # configurazione non è valida e non controlla nulla: senza avvisi riconosciuti è un errore.
        text = (out + "\n" + (err or "")).lower()
        has_warning = any(ln.lstrip().lower().startswith(("warning:", "rootkit:")) or "[ warning ]" in ln.lower()
                          for ln in out.splitlines())
        if ("invalid" in text and "configuration option" in text) or (rc == 1 and not has_warning):
            return f"{FAILED_MARKER}\nrc={rc} {(err or out).strip()[:300]}"
        if baseline_created:
            return BASELINE_CREATED_MARKER + out
        return out

    def post_install(self, executor: BaseExecutor, tracker, sudo_ctx=None) -> None:
        """rkhunter installato dall'assessment: anche la baseline e il log creati vanno tolti.

        La rimozione del pacchetto lascia /var/lib/rkhunter: senza questo, una baseline
        scritta da noi resterebbe sul sistema e verrebbe scambiata per quella dell'admin.
        """
        track_new_files(executor, tracker, "rkhunter-db", CREATED_FILES)

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_rkhunter(raw_output)
