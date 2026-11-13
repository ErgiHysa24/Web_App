"""chkrootkit integration."""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import privileges
from risk_assessor.models import Finding
from risk_assessor.parsers.chkrootkit import FAILED_MARKER, SUDO_MARKER, parse_chkrootkit
from risk_assessor.tools.base import SecurityTool


class ChkrootkitTool(SecurityTool):
    name = "chkrootkit"
    package = "chkrootkit"
    # Pacchettizzato solo da Debian/Ubuntu e Fedora. Senza `strings` (binutils) non
    # controlla nulla ("can't find strings"), e non sempre arriva come dipendenza.
    packages = {"debian": ["chkrootkit", "binutils"], "fedora": ["chkrootkit", "binutils"],
                "rhel": None, "suse": None, "arch": None, "alpine": None}

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # chkrootkit deve leggere /proc, /dev e i binari di sistema: senza root
        # i suoi controlli non sono affidabili, quindi non lo si esegue.
        priv = privileges(executor)
        if priv is None:
            return SUDO_MARKER
        out, err, rc = executor.execute_command(priv + [self._path, "-q"])
        if rc != 0 and not (out or "").strip():
            # Nessun output e uscita con errore: il controllo non è avvenuto.
            return f"{FAILED_MARKER} rc={rc}\n{(err or '').strip()[:300]}"
        return out or ""

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_chkrootkit(raw_output)
