"""Parser dell'output di `debsecan --suite <codename> --only-fixed --format summary`.

Formato reale (una riga per CVE e pacchetto binario; verificato su Debian 12 e 13):

    CVE-2024-28085 bsdutils (fixed)
    CVE-2024-2961 libc-bin (remotely exploitable, high urgency, fixed)

Tra parentesi ci sono gli attributi della vulnerabilità. Qualsiasi errore di debsecan
(rete verso il security tracker, opzioni) arriva come FAILED_MARKER e diventa un finding
"non completato": l'assenza di righe vale come "nessuna vulnerabilità" SOLO se il
programma è terminato correttamente senza scrivere nulla.
"""
from __future__ import annotations
import re

from risk_assessor.sanitize import safe_shell_arg
from risk_assessor.models import Finding, Severity, Confidence

FAILED_MARKER = "__DEBSECAN_FAILED__"

_LINE_RE = re.compile(r"^(CVE-\d{4}-\d{4,7})\s+(\S+)(?:\s+\(([^)]*)\))?\s*$")


def _failed(detail: str) -> Finding:
    return Finding(
        title="debsecan: controllo non completato",
        category="vulnerabilities",
        severity=Severity.INFO,
        description=("debsecan non ha completato l'analisi (per esempio senza accesso a "
                     "security-tracker.debian.org): l'assenza di segnalazioni NON significa che i "
                     "pacchetti siano aggiornati."),
        evidence=detail.strip()[:500],
        recommendation="Verificare l'accesso a internet del sistema e rieseguire debsecan a mano.",
        source="debsecan:failed",
        confidence=Confidence.LOW,
    )


def parse_debsecan(text: str) -> list[Finding]:
    if text.startswith(FAILED_MARKER):
        return [_failed(text[len(FAILED_MARKER):])]
    if not text or not text.strip():
        return [Finding(
            title="debsecan: nessuna vulnerabilità con correzione disponibile",
            category="vulnerabilities",
            severity=Severity.INFO,
            description="debsecan non ha trovato CVE per cui esiste già un aggiornamento.",
            evidence="",
            recommendation="Nessuna azione richiesta.",
            source="debsecan:summary",
            confidence=Confidence.MEDIUM,
        )]

    by_package: dict[str, list[tuple[str, str]]] = {}
    total = 0
    for raw in text.splitlines():
        m = _LINE_RE.match(raw.strip())
        if not m:
            continue
        cve, package, flags = m.group(1), m.group(2), (m.group(3) or "").lower()
        by_package.setdefault(package, []).append((cve, flags))
        total += 1

    if not total:
        # Ha scritto qualcosa ma nessuna riga è una CVE: non è un "tutto a posto".
        return [_failed("output non riconosciuto: " + " | ".join(text.strip().splitlines()[:3]))]

    findings: list[Finding] = []
    for package, cves in sorted(by_package.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        flags = " ".join(f for _, f in cves)
        serious = "high urgency" in flags or "remotely exploitable" in flags
        notes = [label for key, label in (("remotely exploitable", "sfruttabili da remoto"),
                                          ("high urgency", "urgenza alta")) if key in flags]
        findings.append(Finding(
            title=f"debsecan: {len(cves)} CVE in {package}",
            category="vulnerabilities",
            severity=Severity.HIGH if serious or len(cves) >= 3 else Severity.MEDIUM,
            description=(f"Il pacchetto '{package}' ha {len(cves)} vulnerabilità note già corrette "
                         "negli aggiornamenti di Debian" + (f" ({', '.join(notes)})" if notes else "") + "."),
            evidence=", ".join(c for c, _ in cves[:15])[:500],
            recommendation=f"Aggiornare {package} all'ultima versione disponibile.",
            source="debsecan:package",
            confidence=Confidence.HIGH,
            command=(f"sudo apt-get install --only-upgrade {arg}" if (arg := safe_shell_arg(package)) else ""),
        ))

    findings.append(Finding(
        title=f"debsecan: {total} CVE totali su {len(by_package)} pacchetti",
        category="vulnerabilities",
        severity=Severity.INFO,
        description=f"Riepilogo: {total} CVE con correzione disponibile su {len(by_package)} pacchetti.",
        evidence=f"pacchetti affetti: {', '.join(by_package.keys())[:200]}",
        recommendation="Applicare gli aggiornamenti di sicurezza: sudo apt-get update && sudo apt-get upgrade.",
        source="debsecan:summary",
        confidence=Confidence.HIGH,
        command="sudo apt-get update && sudo apt-get upgrade",
    ))
    return findings
