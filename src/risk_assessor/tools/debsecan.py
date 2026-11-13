"""debsecan: vulnerabilità note dei pacchetti con correzione già pubblicata (solo Debian)."""
from __future__ import annotations

import re

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.models import Finding
from risk_assessor.parsers.debsecan import FAILED_MARKER, parse_debsecan
from risk_assessor.tools.base import SecurityTool


# Scarica i dati del security tracker di Debian: qualche secondo, di più su reti lente.
DEBSECAN_TIMEOUT = 300


class DebsecanTool(SecurityTool):
    name = "debsecan"
    package = "debsecan"
    packages = {"debian": ["debsecan"]}

    def unsupported_reason(self, host: HostInfo) -> str | None:
        # debsecan usa il security tracker di Debian: su Ubuntu e sulle altre derivate
        # darebbe risultati sbagliati (versioni e correzioni diverse).
        if host.system != "unknown" and host.distro_id != "debian":
            return f"solo per Debian (su {host.pretty or host.family_label} usare Trivy)"
        return None

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # --only-fixed richiede --suite (senza, debsecan esce con un errore): il nome in
        # codice della release viene da /etc/os-release (VERSION_CODENAME).
        suite = host_info(executor).codename
        if not re.fullmatch(r"[a-z]{2,20}", suite or ""):
            return f"{FAILED_MARKER}\nnome in codice della release non disponibile (VERSION_CODENAME)"
        out, err, rc = executor.execute_command(
            [self._path, "--suite", suite, "--only-fixed", "--format", "summary"],
            timeout=DEBSECAN_TIMEOUT,
        )
        if rc != 0:
            return f"{FAILED_MARKER}\n{(err or out or f'codice di uscita {rc}').strip()[:300]}"
        return out or ""

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_debsecan(raw_output)
