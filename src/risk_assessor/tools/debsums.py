"""debsums integration (solo Debian/Ubuntu).

debsums verifica l'integrità dei file installati confrontandoli con i checksum dei
pacchetti: trova file di sistema modificati o cancellati già alla prima esecuzione,
senza bisogno di una baseline (a differenza di AIDE).
"""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Finding
from risk_assessor.parsers.debsums import FAILED_MARKER, parse_debsums
from risk_assessor.host import privileged_prefix
from risk_assessor.tools.base import SecurityTool

# Legge tutti i file dei pacchetti: su dischi lenti può richiedere qualche minuto.
DEBSUMS_TIMEOUT = 1800


class DebsumsTool(SecurityTool):
    name = "debsums"
    package = "debsums"
    # Usa i checksum di dpkg: esiste solo su Debian e derivate.
    packages = {"debian": ["debsums"], "fedora": None, "rhel": None, "suse": None,
                "arch": None, "alpine": None}

    def unsupported_reason(self, host):
        if host.is_linux and host.family != "debian":
            return f"solo per Debian e derivate (non per {host.pretty or host.family_label})"
        return super().unsupported_reason(host)

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # Come root (sudo -n, se disponibile) debsums legge anche i file protetti.
        prefix = privileged_prefix(executor)
        out, err, rc = executor.execute_command(
            prefix + [self._path, "-c"], timeout=DEBSUMS_TIMEOUT,
        )
        # rc: 0 tutto a posto, 1 file mancanti, 2 file modificati. Altro = errore.
        if rc not in (0, 1, 2):
            return f"{FAILED_MARKER}\n{err or out or f'codice di uscita {rc}'}"
        combined = (out or "") + "\n" + (err or "")
        if rc != 0 and not any(
            ln.startswith(("/", "debsums:")) for ln in combined.splitlines()
        ):
            # Uscita diversa da 0 ma nessuna riga riconoscibile (per esempio il testo
            # d'uso per un'opzione errata): non può valere come "nessun file modificato".
            return f"{FAILED_MARKER}\n{combined.strip() or f'codice di uscita {rc}'}"
        return combined

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_debsums(raw_output)
