"""Parser for AIDE (Advanced Intrusion Detection Environment) output.

AIDE produce un report testuale tipo:

    AIDE found differences between database and filesystem!!
    Start timestamp: 2026-10-13 10:00:00
    Summary:
      Total number of entries:      12345
      Added entries:                2
      Removed entries:              0
      Changed entries:              3

    Changed entries:
    f   ...    .C.. : /etc/passwd
    f   ...    .C.. : /usr/bin/sudo
    d   ...    .C.. : /etc/ssh

Dove la colonna con "C" indica Changed, "A" Added, "R" Removed (AIDE fino alla 0.15).
Dalla 0.16 le righe delle sezioni hanno gli attributi in un altro formato
("f   ...    mc..H.. : /usr/bin/sudo", "f+++++++++++++++++ : /etc/new"): dentro una
sezione si prende il percorso dopo " : " qualunque sia la colonna degli attributi.
I conteggi del riepilogo ("Changed entries: 2") prevalgono sempre: se dicono che ci
sono differenze, il report non può dire "nessuna modifica".
"""
from __future__ import annotations
import re

from risk_assessor.models import Finding, Severity, Confidence


# Marker emesso da AideTool quando ha creato il database al primo avvio
BASELINE_CREATED_MARKER = "__AIDE_BASELINE_CREATED__"
# AIDE era già installato ma senza database: l'assessment non lo crea (sarebbe una baseline sua)
NO_DATABASE_MARKER = "__AIDE_NO_DATABASE__"

# Header di sezione: "Added entries:", "Removed entries:", "Changed entries:"
_SECTION_RE = re.compile(r"^\s*(Added|Removed|Changed)\s+entries?:\s*$", re.IGNORECASE)
# Riga di summary: "Added entries: 2" (con numero dopo i due punti)
_SUMMARY_RE = re.compile(r"^\s*(Added|Removed|Changed)\s+entries?:\s*(\d+)\s*$",
                        re.IGNORECASE)
# Formato sezione: "f++++++++++++++++: /etc/newfile.conf" (Added)
_SECTION_ENTRY_RE = re.compile(r"^\s*[fdls][+\-]{3,}\s*:\s*(.+)$")
# Formato tabella: "f   ...    .C.. : /etc/passwd"
_TABLE_ENTRY_RE = re.compile(r"^\s*([fdls])\s+\S+\s+\.([ACR]+)\.\S*\s*:\s*(.+)$")
# Qualsiasi riga di voce dentro una sezione (tutte le versioni): "<tipo><attributi> : /percorso"
_ANY_ENTRY_RE = re.compile(r"^\s*[A-Za-z!=<>+\-][^:]*?\s*:\s*(/.*)$")


# Frasi che AIDE stampa solo quando il confronto è stato davvero eseguito
_RECOGNIZED_RE = re.compile(
    r"AIDE found (NO )?differences|Total number of (entries|files)|Looks okay", re.IGNORECASE)


def _count(entries: list[str], summary: dict[str, int], kind: str) -> int:
    """Numero di voci: quello del riepilogo se c'è, altrimenti quelle elencate."""
    listed = len([e for e in entries if not e.startswith("(altri ")])
    return max(summary.get(kind, 0), listed)


def parse_aide(text: str) -> list[Finding]:
    if text == "__SUDO_REQUIRED__":
        return [Finding(
            title="AIDE: richiede privilegi root",
            category="integrity",
            severity=Severity.INFO,
            description=(
                "AIDE richiede privilegi root per accedere a /var/lib/aide/ "
                "e /etc/aide/aide.conf. NOPASSWD non è configurato."
            ),
            evidence="sudo -n true ha fallito",
            recommendation=(
                "Configurare NOPASSWD nel sudoers per l'utente "
                "(--ask-sudo-password vale solo per installazione e rimozione dei tool)."
            ),
            source="aide:sudo-required",
            confidence=Confidence.HIGH,
        )]

    if text == NO_DATABASE_MARKER:
        return [Finding(
            title="AIDE installato ma senza database: integrità non verificata",
            category="integrity",
            severity=Severity.LOW,
            description=("AIDE è presente sul sistema ma il suo database (/var/lib/aide/aide.db) non esiste: "
                         "non c'è una baseline con cui confrontare i file. L'assessment non la crea, perché "
                         "deve essere scattata dall'amministratore su un sistema noto come integro."),
            evidence="/var/lib/aide/aide.db assente",
            recommendation="Inizializzare il database (aide --init) su un sistema integro e copiarlo in aide.db.",
            source="aide:no-database",
            confidence=Confidence.HIGH,
        )]

    if text == BASELINE_CREATED_MARKER:
        return [Finding(
            title="AIDE: baseline creata, nessun confronto possibile",
            category="integrity",
            severity=Severity.INFO,
            description=(
                "Il database AIDE non esisteva ed è stato inizializzato ora. "
                "Alla prima esecuzione non c'è nulla con cui confrontare, quindi "
                "il controllo di integrità non è stato eseguito."
            ),
            evidence="/var/lib/aide/aide.db assente prima dell'assessment",
            recommendation=(
                "Inizializzare il database su un sistema noto come integro e "
                "ripetere l'assessment: il controllo diventerà significativo."
            ),
            source="aide:baseline-created",
            confidence=Confidence.HIGH,
        )]

    if not text or not text.strip():
        return [Finding(
            title="AIDE: nessun output",
            category="integrity",
            severity=Severity.INFO,
            description="AIDE non ha prodotto output.",
            evidence="",
            recommendation="Verificare che AIDE sia installato e il database inizializzato.",
            source="aide:summary",
            confidence=Confidence.LOW,
        )]

    findings: list[Finding] = []
    summary: dict[str, int] = {}
    added: list[str] = []
    removed: list[str] = []
    changed: list[str] = []

    current_section: str | None = None  # "added", "removed", "changed"

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip().startswith("---"):
            continue

        # Header di sezione ("Added entries:")
        m = _SECTION_RE.match(line)
        if m:
            current_section = m.group(1).lower()
            continue
        # Qualsiasi altra intestazione ("Detailed information about changes:", "The attributes
        # of the database(s):") chiude la sezione: le sue righe non sono voci.
        if line.rstrip().endswith(":") and not line[:1].isspace():
            current_section = None
            continue

        # Summary con numero ("Added entries: 2")
        m = _SUMMARY_RE.match(line)
        if m:
            kind = m.group(1).lower()
            try:
                summary[kind] = int(m.group(2))
            except ValueError:
                pass
            continue

        # Entry nel formato sezione ("f++++: /path")
        m = _SECTION_ENTRY_RE.match(line)
        if m:
            path = m.group(1).strip()
            if current_section == "added":
                added.append(path)
            elif current_section == "removed":
                removed.append(path)
            elif current_section == "changed":
                changed.append(path)
            continue

        # Entry dentro una sezione, qualunque formato di attributi (AIDE >= 0.16)
        m = _ANY_ENTRY_RE.match(line) if current_section and not _TABLE_ENTRY_RE.match(line) else None
        if m:
            path = m.group(1).strip()
            target = {"added": added, "removed": removed, "changed": changed}[current_section]
            if path not in target:
                target.append(path)
            continue

        # Entry nel formato tabella ("f ... .C.. : /path")
        m = _TABLE_ENTRY_RE.match(line)
        if m:
            flags = m.group(2)
            path = m.group(3).strip()
            if "A" in flags and path not in added:
                added.append(path)
            if "R" in flags and path not in removed:
                removed.append(path)
            if "C" in flags and path not in changed:
                changed.append(path)

    # I conteggi del riepilogo prevalgono: un elenco non riconosciuto non diventa "nessuna modifica".
    unparsed = {k: summary.get(k, 0) - len(v) for k, v in
                (("added", added), ("removed", removed), ("changed", changed)) if summary.get(k, 0) > len(v)}
    for kind, missing in unparsed.items():
        target = {"added": added, "removed": removed, "changed": changed}[kind]
        target.extend([f"(altri {missing}: dettaglio non riconosciuto, vedi 'aide --check')"])

    # Se ci sono cambiamenti, produci finding mirati
    if removed:
        findings.append(Finding(
            title=f"AIDE: {_count(removed, summary, "removed")} file rimossi",
            category="integrity",
            severity=Severity.HIGH,
            description=(
                f"AIDE ha rilevato la rimozione di {_count(removed, summary, "removed")} file di sistema. "
                "Rimozioni non pianificate possono indicare manomissione."
            ),
            evidence="\n".join(removed[:15])[:500],
            recommendation="Verificare ogni rimozione. Ripristinare se non autorizzata.",
            source="aide:removed",
            confidence=Confidence.HIGH,
        ))

    if changed:
        findings.append(Finding(
            title=f"AIDE: {_count(changed, summary, "changed")} file modificati",
            category="integrity",
            severity=Severity.MEDIUM,
            description=(
                f"AIDE ha rilevato modifiche a {_count(changed, summary, "changed")} file di sistema "
                "rispetto al database."
            ),
            evidence="\n".join(changed[:15])[:500],
            recommendation=(
                "Verificare se le modifiche sono autorizzate. "
                "Aggiornare il database con 'aide --update' dopo la verifica."
            ),
            source="aide:changed",
            confidence=Confidence.MEDIUM,
        ))

    if added:
        findings.append(Finding(
            title=f"AIDE: {_count(added, summary, "added")} file aggiunti",
            category="integrity",
            severity=Severity.MEDIUM,
            description=(
                f"AIDE ha rilevato l'aggiunta di {_count(added, summary, "added")} file di sistema. "
                "Aggiunte non pianificate possono indicare persistenza."
            ),
            evidence="\n".join(added[:15])[:500],
            recommendation="Verificare ogni aggiunta. Rimuovere se non autorizzata.",
            source="aide:added",
            confidence=Confidence.MEDIUM,
        ))

    # Output non riconosciuto: un errore di AIDE non deve passare per "sistema pulito".
    recognized = bool(summary or added or removed or changed or _RECOGNIZED_RE.search(text))
    if not recognized:
        return [Finding(
            title="AIDE: output non riconosciuto, controllo non verificabile",
            category="integrity",
            severity=Severity.INFO,
            description=(
                "L'output di AIDE non contiene né un riepilogo né un elenco di differenze: "
                "probabilmente AIDE ha dato un errore (database mancante o non valido, "
                "configurazione). Il controllo di integrità NON è stato eseguito."
            ),
            evidence=text.strip()[:500],
            recommendation=(
                "Eseguire 'sudo aide --check' sulla macchina per vedere l'errore, "
                "inizializzare il database ('sudo aide --init') e ripetere."
            ),
            source="aide:unrecognized",
            confidence=Confidence.LOW,
        )]

    # Summary
    if not findings:
        ev = ", ".join(f"{k}={v}" for k, v in summary.items()) if summary else "no summary"
        findings.append(Finding(
            title="AIDE: nessuna modifica rilevata",
            category="integrity",
            severity=Severity.INFO,
            description="AIDE non ha rilevato modifiche ai file di sistema.",
            evidence=ev[:500],
            recommendation="Nessuna azione richiesta.",
            source="aide:summary",
            confidence=Confidence.HIGH,
        ))
    else:
        ev = ", ".join(f"{k}={v}" for k, v in summary.items())[:500] if summary else ""
        findings.append(Finding(
            title=f"AIDE: {sum(_count(v, summary, k) for k, v in (('changed', changed), ('added', added), ('removed', removed)))} modifiche rilevate",
            category="integrity",
            severity=Severity.INFO,
            description="Riepilogo del controllo di integrità AIDE.",
            evidence=ev,
            recommendation="Investigare le modifiche rilevate.",
            source="aide:summary",
            confidence=Confidence.MEDIUM,
        ))

    return findings
