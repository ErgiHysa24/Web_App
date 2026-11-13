"""Parser for ClamAV (clamscan) output.

Output tipico con `--infected`:

    /tmp/eicar.txt: Eicar-Test-Signature FOUND
    /home/user/malware.bin: Win.Trojan.Agent FOUND
    ----------- SCAN SUMMARY -----------
    Known viruses: 8523123
    Infected files: 2
    Time: 12.345 sec

Solo le righe con "FOUND" indicano infezioni.
"""
from __future__ import annotations
import re

from risk_assessor.models import Finding, Severity, Confidence


# "/path/to/file: VirusName FOUND"
_INFECTED_RE = re.compile(r"^(?P<path>.+?):\s+(?P<signature>.+?)\s+FOUND\s*$")
# Righe di summary
_SUMMARY_RE = re.compile(r"^(Known viruses|Engine version|Scanned files|"
                        r"Scanned directories|Infected files|Data scanned|Time):\s*(.+)$")


def _failed(detail: str) -> list[Finding]:
    return [Finding(
        title="ClamAV: scansione non completata",
        category="malware",
        severity=Severity.INFO,
        description=(
            "La scansione ClamAV non è avvenuta o non ha controllato nessun file "
            "(per esempio database delle firme assente). Questo NON significa che il sistema sia pulito."
        ),
        evidence=detail[:500],
        recommendation=(
            "Verificare che il database delle firme sia presente "
            "(`sudo freshclam`, serve accesso a internet) e rilanciare."
        ),
        source="clamav:failed",
        confidence=Confidence.HIGH,
    )]


def parse_clamav(text: str) -> list[Finding]:
    if text and text.lstrip().startswith("__CLAMAV_FAILED__"):
        return _failed(text.lstrip()[len("__CLAMAV_FAILED__"):].strip())

    if not text or not text.strip():
        return [Finding(
            title="ClamAV: nessun output",
            category="malware",
            severity=Severity.INFO,
            description="clamscan non ha prodotto output.",
            evidence="",
            recommendation="Verificare che ClamAV sia installato e il database aggiornato.",
            source="clamav:summary",
            confidence=Confidence.LOW,
        )]

    findings: list[Finding] = []
    infected_files: list[tuple[str, str]] = []
    summary: dict[str, str] = {}

    partial = "__CLAMAV_PARTIAL__" in text
    partial_detail = ""
    if partial:
        text, _, partial_detail = text.partition("__CLAMAV_PARTIAL__")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _INFECTED_RE.match(line)
        if m:
            infected_files.append((m.group("path"), m.group("signature")))
            continue

        m = _SUMMARY_RE.match(line)
        if m:
            summary[m.group(1)] = m.group(2).strip()

    # Un finding per ogni file infetto
    for path, signature in infected_files:
        findings.append(Finding(
            title=f"ClamAV: malware rilevato in {path[:60]}",
            category="malware",
            severity=Severity.CRITICAL,
            description=(
                f"ClamAV ha rilevato '{signature}' nel file {path}. "
                "Richiede quarantena e investigazione immediata."
            ),
            evidence=f"{path}: {signature} FOUND",
            recommendation="Isolare il file, verificare la provenienza, "
                           "eseguire scansione completa. Non eseguire il file.",
            source="clamav:infected",
            confidence=Confidence.HIGH,
        ))

    # Il riepilogo c'è ma non è stato controllato nulla: per esempio database delle
    # firme vuoto ("Known viruses: 0") o nessun file letto. Non è un "pulito".
    if not infected_files and (summary.get("Known viruses") == "0"
                               or summary.get("Scanned files") == "0"):
        return _failed(", ".join(f"{k}={v}" for k, v in summary.items())
                       + ("\n" + partial_detail.strip() if partial else ""))

    # Summary
    if infected_files:
        findings.append(Finding(
            title=f"ClamAV: {len(infected_files)} file infetti",
            category="malware",
            severity=Severity.INFO,
            description="Riepilogo scansione ClamAV.",
            evidence="\n".join(f"{p}: {s}" for p, s in infected_files[:10])[:500],
            recommendation="Analizzare tutti i file infetti trovati.",
            source="clamav:summary",
            confidence=Confidence.MEDIUM,
        ))
    else:
        # Nessuna infezione
        ev = ", ".join(f"{k}={v}" for k, v in summary.items()) or "no summary"
        if partial:
            findings.append(Finding(
                title="ClamAV: nessuna infezione rilevata (scansione parziale)",
                category="malware",
                severity=Severity.INFO,
                description=(
                    "La scansione ClamAV non ha trovato malware, ma alcuni file non sono "
                    "stati letti (di solito per mancanza di permessi): quei file non sono controllati."
                ),
                evidence=(ev + "\n" + partial_detail.strip())[:500],
                recommendation="Per una copertura completa eseguire con sudo senza password.",
                source="clamav:summary",
                confidence=Confidence.MEDIUM,
            ))
            return findings
        findings.append(Finding(
            title="ClamAV: nessuna infezione rilevata",
            category="malware",
            severity=Severity.INFO,
            description="La scansione ClamAV non ha trovato malware nei path scansionati.",
            evidence=ev[:500],
            recommendation="Nessuna azione richiesta.",
            source="clamav:summary",
            confidence=Confidence.HIGH,
        ))

    return findings
