"""Nmap integration."""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.parsers.nmap import extract_open_ports, parse_nmap_xml
from risk_assessor.tools.base import SecurityTool


FAILED_MARKER = "__NMAP_FAILED__"


class NmapTool(SecurityTool):
    name = "nmap"
    package = "nmap"
    # Su Alpine il motore degli script (nse_main.lua, in nmap-nselibs) e gli script stanno in
    # pacchetti separati, e -sV ne ha bisogno: senza, nmap si ferma con "could not locate
    # nse_main.lua". nmap-scripts dipende da nmap-nselibs.
    packages = {"alpine": ["nmap", "nmap-scripts"], "*": ["nmap"]}
    platforms = frozenset({"linux", "darwin"})
    open_ports: set[tuple[int, str]] | None = None   # porte viste dall'interno (dopo parse)

    def version(self, executor: BaseExecutor) -> str | None:
        out, _, rc = executor.execute_command([self._path, "--version"])
        if rc != 0 or not out:
            return None
        first = out.splitlines()[0] if out.splitlines() else ""
        for token in first.split():
            if token and token[0].isdigit():
                return token
        return first.strip() or None

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        target = target or "127.0.0.1"
        # -Pn: la macchina analizzata è per definizione accesa. Senza, in alcuni ambienti
        # (container, firewall che scarta i ping) nmap dichiara l'host "down" e non
        # scansiona nessuna porta.
        cmd = [self._path, "-sV", "-T4", "-F", "-Pn", "-oX", "-", target]
        out, err, rc = executor.execute_command(cmd)
        if "<nmaprun" not in (out or ""):
            # Niente XML: la scansione non è avvenuta (non "nessuna porta aperta").
            return f"{FAILED_MARKER}\nrc={rc} {(err or out or '').strip()[:300]}"
        return out

    def parse(self, raw_output: str) -> list[Finding]:
        if raw_output.startswith(FAILED_MARKER):
            self.open_ports = None
            return [Finding(
                title="Nmap: scansione non completata",
                category="network",
                severity=Severity.INFO,
                description=("Nmap non ha prodotto risultati: le porte aperte non sono state "
                             "verificate (non significa che siano tutte chiuse)."),
                evidence=raw_output[len(FAILED_MARKER):].strip()[:500],
                recommendation="Eseguire nmap a mano sul sistema per vedere l'errore.",
                source="nmap:failed",
                confidence=Confidence.LOW,
            )]
        findings = parse_nmap_xml(raw_output)
        # Senza una scansione riuscita non si sa quali porte sono aperte (None, non "nessuna"):
        # il confronto con la scansione dall'esterno non deve partire da un insieme vuoto.
        failed = any(f.source == "nmap:failed" for f in findings)
        self.open_ports = None if failed else extract_open_ports(raw_output)
        return findings
