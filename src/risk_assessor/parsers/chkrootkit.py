"""Parser for chkrootkit output.

chkrootkit produce output tipo:
  Checking `ls'... not infected
  Checking `ps'... INFECTED
  eth0: PACKET SNIFFER(/sbin/dhclient[1234])

Righe con "INFECTED" o "Vulnerable" o "PACKET SNIFFER" sono segnalazioni, come le
righe "WARNING:", "Possible ..." e i file/cartelle sospetti (con l'elenco dei percorsi
nelle righe seguenti). "not found", "nothing found" e "not tested" non lo sono.
"""
from __future__ import annotations
import re

from risk_assessor.models import Finding, Severity, Confidence
from risk_assessor.sanitize import clean_text


SUDO_MARKER = "__SUDO_REQUIRED__"
FAILED_MARKER = "__CHKROOTKIT_FAILED__"

_INFECTED_RE = re.compile(r"(?<!not\s)\bINFECTED\b", re.IGNORECASE)
_VULN_RE = re.compile(r"\bVulnerable\b", re.IGNORECASE)
_SNIFFER_RE = re.compile(r"PACKET SNIFFER", re.IGNORECASE)
_WARNING_RE = re.compile(r"(^|\.\.\.\s*)(WARNING\b|Possible\b)|\bsuspicious\b.*\bfound\b",
                         re.IGNORECASE)
_BENIGN = ("not infected", "not vulnerable", "nothing found", "not found", "not tested",
           "nothing detected", "no suspicious", "skipping unsupported filesystem")


def parse_chkrootkit(text: str) -> list[Finding]:
    if text.strip() == SUDO_MARKER:
        return [Finding(
            title="chkrootkit: richiede privilegi root",
            category="rootkit",
            severity=Severity.INFO,
            description=("chkrootkit deve leggere /proc, /dev e i binari di sistema come root: "
                         "senza privilegi il controllo non è stato eseguito."),
            evidence="né root né sudo senza password",
            recommendation="Eseguire l'assessment come root o con sudo senza password (NOPASSWD).",
            source="chkrootkit:sudo-required",
            confidence=Confidence.HIGH,
        )]
    if text.startswith(FAILED_MARKER):
        return [Finding(
            title="chkrootkit: scansione non completata",
            category="rootkit",
            severity=Severity.INFO,
            description=("chkrootkit è terminato con un errore senza produrre risultati: "
                         "l'assenza di segnalazioni NON significa che il sistema sia pulito."),
            evidence=text[len(FAILED_MARKER):].strip()[:500],
            recommendation="Eseguire chkrootkit a mano sul sistema per vedere l'errore.",
            source="chkrootkit:failed",
            confidence=Confidence.LOW,
        )]

    findings: list[Finding] = []
    seen: set[str] = set()

    last: Finding | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            last = None
            continue

        # Elenco dei percorsi sotto una riga "suspicious files ... found": va nell'evidenza.
        if last is not None and last.source == "chkrootkit:suspicious" and line.startswith("/"):
            last.evidence = clean_text(last.evidence + "\n" + line)[:500]
            continue
        last = None

        # "not infected" NON è una segnalazione
        line_lower = line.lower()
        if any(b in line_lower for b in _BENIGN):
            continue

        kind = None
        severity = Severity.MEDIUM
        if _INFECTED_RE.search(line):
            kind = "infected"
            severity = Severity.HIGH
        elif _SNIFFER_RE.search(line):
            kind = "packet-sniffer"
            severity = Severity.HIGH
        elif _VULN_RE.search(line):
            kind = "vulnerable"
            severity = Severity.MEDIUM
        elif _WARNING_RE.search(line):
            kind = "suspicious"
            severity = Severity.MEDIUM
        else:
            continue

        key = line.lower()
        if key in seen:
            continue
        seen.add(key)

        finding = Finding(
            title=f"chkrootkit {kind}: {line[:80]}",
            category="rootkit",
            severity=severity,
            description=(
                f"chkrootkit ha segnalato: {line}. "
                "Potenziale indicatore — richiede investigazione manuale."
            ),
            evidence=line[:500],
            recommendation="Investigare manualmente e verificare falsi positivi.",
            source=f"chkrootkit:{kind}",
            confidence=Confidence.LOW,
        )
        findings.append(finding)
        last = finding

    if findings:
        findings.append(Finding(
            title=f"chkrootkit: {len(findings)} segnalazioni",
            category="rootkit",
            severity=Severity.INFO,
            description=f"chkrootkit ha prodotto {len(findings)} segnalazioni.",
            evidence="\n".join(f.evidence for f in findings[:5])[:500],
            recommendation="Verificare ogni segnalazione.",
            source="chkrootkit:summary",
            confidence=Confidence.MEDIUM,
        ))
    else:
        findings.append(Finding(
            title="chkrootkit: 0 segnalazioni",
            category="rootkit",
            severity=Severity.INFO,
            description="chkrootkit non ha rilevato infezioni o sniffer.",
            evidence="Nessuna riga contenente INFECTED, Vulnerable, PACKET SNIFFER, WARNING o Possible.",
            recommendation="Nessuna azione richiesta.",
            source="chkrootkit:summary",
            confidence=Confidence.MEDIUM,
        ))

    return findings
