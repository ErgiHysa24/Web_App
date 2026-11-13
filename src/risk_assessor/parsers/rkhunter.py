"""Parser for rkhunter output.

rkhunter produce output testuale tipo:
  [ Warning ] ...
  [ Rootkit ] ...
  [ Info ] ...

Warning e Rootkit sono "indicatori da investigare", non conferme.
"""
from __future__ import annotations
import re

from risk_assessor.models import Finding, Severity, Confidence


# "[ Warning ] Some text" oppure "[Warning] Some text"
_LINE_RE = re.compile(r"\[\s*(Warning|Rootkit|Info|None)\s*\]\s*(.+)")
# Formato di --report-warnings-only: "Warning: The command '/usr/bin/x' has been replaced..."
_PLAIN_RE = re.compile(r"^(Warning|Rootkit):\s*(.+)")

# Avvisi che riguardano rkhunter stesso o l'ambiente, non il sistema: configurazione e
# database di rkhunter, prima esecuzione, container senza moduli del kernel, opzioni SSH
# obsolete. Si raccolgono in un solo finding informativo invece di tanti MEDIUM.
_SETUP_PATTERNS = (
    "checking for prerequisites",
    "is missing or empty",                     # file dei dati di rkhunter, /lib/modules nei container
    "unable to check for",                     # prima esecuzione: nessuna copia di passwd/group
    "rkhunter configuration options should be the same",
    "the ssh and rkhunter configuration",
    "configuration option 'protocol'",         # Protocol non esiste più da OpenSSH 7.4
    "no copy of the",
    "unable to determine",
)
# File nascosti normali (systemd, shadow-utils): non sono indizi.
_BENIGN_HIDDEN = ("/etc/.updated", "/etc/.pwd.lock", "/dev/.lxc", "/etc/.java", "/dev/.udev")

# Prima riga sintetica emessa dal tool quando ha creato la baseline
BASELINE_CREATED_MARKER = "__BASELINE_CREATED__\n"
FAILED_MARKER = "__RKHUNTER_FAILED__"


def parse_rkhunter(text: str) -> list[Finding]:
    if text.startswith(FAILED_MARKER):
        return [Finding(
            title="rkhunter: controllo non completato",
            category="rootkit",
            severity=Severity.INFO,
            description=("rkhunter è terminato con un errore: l'assenza di avvisi NON significa che "
                         "il sistema sia pulito."),
            evidence=text[len(FAILED_MARKER):].strip()[:500],
            recommendation="Eseguire 'rkhunter --check' a mano per vedere l'errore.",
            source="rkhunter:failed",
            confidence=Confidence.LOW,
        )]
    if text == "__SUDO_REQUIRED__":
        return [Finding(
            title="rkhunter: richiede privilegi root",
            category="rootkit",
            severity=Severity.INFO,
            description=(
                "rkhunter richiede root per aggiornare la baseline in "
                "/var/lib/rkhunter/ e leggere file di sistema protetti."
            ),
            evidence="sudo -n true ha fallito",
            recommendation=(
                "Configurare NOPASSWD nel sudoers per l'utente "
                "(--ask-sudo-password vale solo per installazione e rimozione dei tool)."
            ),
            source="rkhunter:sudo-required",
            confidence=Confidence.HIGH,
        )]

    # Marker aggiunto da RkhunterTool quando la baseline non esisteva ed è stata
    # creata durante questo assessment (vedi tools/rkhunter.py).
    baseline_created = text.startswith(BASELINE_CREATED_MARKER)
    if baseline_created:
        text = text[len(BASELINE_CREATED_MARKER):]

    findings: list[Finding] = []
    seen: set[str] = set()

    # Due formati: "[ Warning ] testo" (output normale) e "Warning: testo" (con
    # --report-warnings-only, quello usato dallo strumento), con eventuali righe di
    # continuazione rientrate (per esempio l'elenco dei file sospetti).
    entries: list[tuple[str, str, list[str]]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        plain = _PLAIN_RE.match(raw_line)
        m = plain or _LINE_RE.search(raw_line.strip())
        if m:
            entries.append((m.group(1).strip(), m.group(2).strip(), []))
        elif raw_line[:1].isspace() and entries:
            entries[-1][2].append(raw_line.strip())

    setup: list[str] = []
    for kind, msg, details in entries:
        if kind not in ("Warning", "Rootkit"):
            continue
        low = msg.lower()
        if kind == "Warning" and (any(p in low for p in _SETUP_PATTERNS)
                                  or ("hidden" in low and any(b in low for b in _BENIGN_HIDDEN))):
            if msg not in setup:
                setup.append(msg)
            continue
        # deduplica
        key = msg.lower()
        if key in seen:
            continue
        seen.add(key)

        rootkit = kind == "Rootkit" or ("rootkit" in msg.lower() and "found" in msg.lower())
        severity = Severity.HIGH if rootkit else Severity.MEDIUM
        label = "Rootkit" if rootkit else kind
        evidence = "\n".join([msg, *details[:8]])
        findings.append(Finding(
            title=f"rkhunter {label}: {msg[:80]}",
            category="rootkit",
            severity=severity,
            description=(
                f"rkhunter ha segnalato: {msg}. "
                "Questo è un indicatore da investigare, non una conferma di compromissione."
            ),
            evidence=evidence[:500],
            recommendation="Investigare manualmente e verificare falsi positivi.",
            source=f"rkhunter:{label.lower()}",
            confidence=Confidence.LOW,
        ))

    if setup:
        findings.append(Finding(
            title=f"rkhunter: avvisi sulla propria configurazione o sull'ambiente ({len(setup)})",
            category="rootkit",
            severity=Severity.INFO,
            description=("Avvisi che riguardano rkhunter (database, prima esecuzione, opzioni obsolete) o "
                         "l'ambiente (per esempio un container senza moduli del kernel), non segni di "
                         "compromissione del sistema."),
            evidence="\n".join(setup[:10])[:500],
            recommendation="Nessuna azione sul sistema; se rkhunter si usa nel tempo, aggiornarne i dati "
                           "(rkhunter --update, --propupd).",
            source="rkhunter:setup",
            confidence=Confidence.MEDIUM,
        ))

    # Riepilogo: SEMPRE presente, anche con 0 warning
    problems = [f for f in findings if f.source != "rkhunter:setup"]
    if problems:
        findings.append(Finding(
            title=f"rkhunter: {len(problems)} segnalazioni",
            category="rootkit",
            severity=Severity.INFO,
            description=f"rkhunter ha prodotto {len(problems)} segnalazioni (Warning/Rootkit).",
            evidence="\n".join(f.evidence for f in problems[:5])[:500],
            recommendation="Verificare ogni segnalazione.",
            source="rkhunter:summary",
            confidence=Confidence.MEDIUM,
        ))
    else:
        findings.append(Finding(
            title="rkhunter: 0 warning",
            category="rootkit",
            severity=Severity.INFO,
            description="rkhunter non ha prodotto warning.",
            evidence="Nessuna riga di avviso (Warning) nell'output.",
            recommendation="Nessuna azione richiesta.",
            source="rkhunter:summary",
            confidence=Confidence.MEDIUM,
        ))

    if baseline_created:
        findings.append(Finding(
            title="rkhunter: baseline creata durante questo assessment",
            category="rootkit",
            severity=Severity.INFO,
            description=(
                "Sul sistema non esisteva una baseline rkhunter, quindi è stata creata "
                "ora. Il confronto delle proprietà dei file è stato fatto contro uno "
                "stato appena registrato e non può rilevare modifiche precedenti."
            ),
            evidence="/var/lib/rkhunter/db/rkhunter.dat assente prima della scansione",
            recommendation=(
                "Creare la baseline su un sistema noto come integro (rkhunter --propupd) "
                "e ripetere l'assessment per un controllo significativo."
            ),
            source="rkhunter:baseline-created",
            confidence=Confidence.HIGH,
        ))

    return findings
