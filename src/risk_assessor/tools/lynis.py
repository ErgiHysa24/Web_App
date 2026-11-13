"""Lynis integration."""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import privileged_prefix
from risk_assessor.models import Finding
from risk_assessor.parsers.lynis import parse_lynis
from risk_assessor.tools.base import SecurityTool


PID_FILE = "/var/run/lynis.pid"
_LOCK_BUSY = 3
_STALE_LOCK_SCRIPT = (
    '[ -f "$1" ] || exit 0; p=$(cat "$1" 2>/dev/null); '
    'case "$p" in ""|*[!0-9]*) ;; *) kill -0 "$p" 2>/dev/null && exit 3 ;; esac; '
    'rm -f "$1"'
)


class LynisTool(SecurityTool):
    name = "lynis"
    package = "lynis"
    # Su RHEL e derivate Lynis sta in EPEL; su Alpine non è pacchettizzato.
    packages = {"debian": ["lynis"], "fedora": ["lynis"], "rhel": ["lynis"], "suse": ["lynis"],
                "arch": ["lynis"], "alpine": None, "macos": ["lynis"]}
    epel_families = frozenset({"rhel"})
    platforms = frozenset({"linux", "darwin"})

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # Lynis funziona anche senza root ma con meno check: con i privilegi, se ci sono.
        prefix = privileged_prefix(executor)
        # Un lock rimasto da un'esecuzione interrotta farebbe uscire Lynis senza analizzare:
        # si toglie, ma solo se il processo che l'ha scritto non è più in esecuzione.
        _, _, lock_rc = executor.execute_command(prefix + ["sh", "-c", _STALE_LOCK_SCRIPT, "sh", PID_FILE])
        if lock_rc == _LOCK_BUSY:
            return ("Lynis è già in esecuzione su questo sistema (" + PID_FILE + " di un processo attivo): "
                    "audit non eseguito per non interferire.")

        cmd = prefix + [self._path, "audit", "system", "--quick", "--no-colors"]
        # Un Invio su stdin: Lynis installato da Homebrew, eseguito come root, chiede di
        # confermare perché i suoi file non sono di root; senza risposta resterebbe in attesa.
        out, err, rc = executor.execute_command(cmd, stdin="\n")
        # Nessun ripiego su /var/log/lynis-report.dat: potrebbe essere di un audit
        # precedente e farebbe passare per attuale un risultato vecchio.
        return (out or "") + "\n" + (err or "")

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_lynis(raw_output)
