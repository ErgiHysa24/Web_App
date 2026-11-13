"""Parser per l'output di debsums (verifica dei file dei pacchetti Debian/Ubuntu).

debsums confronta l'hash di ogni file installato con quello pubblicato dalla
distribuzione nel pacchetto. Non serve una baseline: già alla prima esecuzione
dice quali file di sistema sono stati modificati o cancellati.

Con `debsums -c` i file modificati escono uno per riga (solo il percorso, su
stdout); i file mancanti escono su stderr come

    debsums: missing file /usr/bin/foo (from foo package)

Il parser accetta anche le forme "debsums: changed file ..." e "/percorso  FAILED".
I file di configurazione (conffile) non sono nei checksum dei pacchetti, quindi non
sono controllati: le modifiche dell'amministratore in /etc non danno falsi allarmi.
"""
from __future__ import annotations

import re

from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.sanitize import clean_text

# Marker emesso da DebsumsTool quando il controllo non è stato completato.
FAILED_MARKER = "__DEBSUMS_FAILED__"

_CHANGED_RE = re.compile(r"^debsums:\s+changed file\s+(\S.*?)\s+\(from\s+\S+\s+package\)\s*$")
_MISSING_RE = re.compile(r"^debsums:\s+missing file\s+(\S.*?)\s+\(from\s+\S+\s+package\)\s*$")
_FAILED_RE = re.compile(r"^(/\S.*?)\s+FAILED\s*$")
_PATH_RE = re.compile(r"^(/[^\s].*)$")
_UNREADABLE_RE = re.compile(r"permission denied|cannot open|can't open|impossibile aprire", re.IGNORECASE)

# Cartelle dei programmi e delle librerie di sistema: una modifica qui è sospetta.
CRITICAL_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/",
    "/lib/", "/lib32/", "/lib64/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/boot/",
)

# Documentazione e traduzioni: le immagini "minimal" le tolgono di proposito, quindi
# file mancanti o modificati qui non sono un segnale di sicurezza.
IGNORED_PREFIXES = (
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/info/",
    "/usr/share/locale/", "/usr/share/lintian/", "/usr/share/help/",
)

# Programmi che un attaccante sostituisce di solito per nascondersi o ottenere accesso.
SENSITIVE_NAMES = frozenset({
    "login", "su", "sudo", "passwd", "sshd", "ssh", "ps", "ls", "netstat", "ss",
    "top", "find", "ifconfig", "lsof", "bash", "sh", "dash", "cron", "crond",
    "pam_unix.so", "sudoedit", "chsh", "chfn", "newgrp",
})


def _is_critical(path: str) -> bool:
    return path.startswith(CRITICAL_PREFIXES)


def _is_ignored(path: str) -> bool:
    return path.startswith(IGNORED_PREFIXES)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _failed(detail: str) -> list[Finding]:
    return [Finding(
        title="debsums: controllo non completato",
        category="integrity",
        severity=Severity.INFO,
        description=(
            "debsums non ha potuto verificare i file dei pacchetti: l'assenza di "
            "segnalazioni NON significa che i file siano integri."
        ),
        evidence=clean_text(detail.strip())[:500],
        recommendation=(
            "Eseguire 'sudo debsums -c' sulla macchina per vedere l'errore "
            "(i checksum sono scaricati dal pacchetto: serve che i pacchetti siano installati normalmente)."
        ),
        source="debsums:failed",
        confidence=Confidence.LOW,
    )]


def _evidence(paths: list[str]) -> str:
    shown = [clean_text(p) for p in paths[:15]]
    extra = f"\n… e altri {len(paths) - 15}" if len(paths) > 15 else ""
    return ("\n".join(shown) + extra)[:500]


def parse_debsums(text: str) -> list[Finding]:
    if text is None:
        return _failed("")
    if text.startswith(FAILED_MARKER):
        return _failed(text[len(FAILED_MARKER):])

    changed: list[str] = []
    missing: list[str] = []
    unreadable = 0

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _UNREADABLE_RE.search(line):
            unreadable += 1
            continue
        m = _MISSING_RE.match(line)
        if m:
            if m.group(1) not in missing:
                missing.append(m.group(1))
            continue
        m = _CHANGED_RE.match(line) or _FAILED_RE.match(line)
        if m:
            if m.group(1) not in changed:
                changed.append(m.group(1))
            continue
        if line.startswith("debsums:"):
            continue          # altri messaggi (es. "no md5sums for ...")
        m = _PATH_RE.match(line)
        if m and m.group(1) not in changed:
            changed.append(m.group(1))

    ignored = [p for p in changed + missing if _is_ignored(p)]
    changed = [p for p in changed if not _is_ignored(p)]
    missing = [p for p in missing if not _is_ignored(p)]

    sensitive = [p for p in changed if _is_critical(p) and _basename(p) in SENSITIVE_NAMES]
    binaries = [p for p in changed if _is_critical(p) and p not in sensitive]
    other = [p for p in changed if not _is_critical(p)]
    gone = [p for p in missing if _is_critical(p)]
    gone_other = [p for p in missing if not _is_critical(p)]

    findings: list[Finding] = []

    if sensitive:
        findings.append(Finding(
            title=f"debsums: {len(sensitive)} programmi di sistema sensibili modificati",
            category="integrity",
            severity=Severity.CRITICAL,
            description=(
                "L'hash di programmi di sistema usati per accedere o per controllare il sistema "
                "(login, su, sudo, ssh, ps, ls…) è diverso da quello del pacchetto. "
                "È il tipico segno di un rootkit che li sostituisce, ma può dipendere "
                "anche da una versione compilata a mano o da un pacchetto non ufficiale."
            ),
            evidence=_evidence(sensitive),
            recommendation=(
                "Verificare l'origine di ogni file; se non è una modifica voluta, considerare "
                "il sistema compromesso e reinstallare il pacchetto (apt install --reinstall <pacchetto>) "
                "o, meglio, ricostruire la macchina da un'immagine pulita."
            ),
            source="debsums:changed-sensitive",
            confidence=Confidence.MEDIUM,
        ))

    if binaries:
        findings.append(Finding(
            title=f"debsums: {len(binaries)} file di programmi e librerie modificati",
            category="integrity",
            severity=Severity.HIGH,
            description=(
                "File installati da un pacchetto in cartelle di programmi e librerie "
                "(/bin, /usr/bin, /usr/lib…) non corrispondono ai checksum della distribuzione. "
                "Può essere una modifica manuale, un aggiornamento incompleto o una manomissione."
            ),
            evidence=_evidence(binaries),
            recommendation=(
                "Capire chi ha modificato i file. Se non è voluto, reinstallare i pacchetti "
                "interessati: apt install --reinstall <pacchetto> ('dpkg -S <file>' dice quale)."
            ),
            source="debsums:changed-binaries",
            confidence=Confidence.MEDIUM,
        ))

    if other:
        findings.append(Finding(
            title=f"debsums: {len(other)} altri file di pacchetti modificati",
            category="integrity",
            severity=Severity.MEDIUM,
            description=(
                "File di pacchetti fuori dalle cartelle dei programmi (per esempio dati o script "
                "in /usr/share, /var, /opt) hanno un hash diverso da quello del pacchetto. "
                "Spesso sono personalizzazioni locali."
            ),
            evidence=_evidence(other),
            recommendation="Verificare che le modifiche siano intenzionali ('dpkg -S <file>' mostra il pacchetto).",
            source="debsums:changed-other",
            confidence=Confidence.LOW,
        ))

    if gone:
        findings.append(Finding(
            title=f"debsums: {len(gone)} file di programmi e librerie mancanti",
            category="integrity",
            severity=Severity.MEDIUM,
            description=(
                "File che un pacchetto dovrebbe installare in cartelle di programmi e librerie "
                "non esistono più. Può essere una cancellazione manuale o un'immagine ridotta di proposito."
            ),
            evidence=_evidence(gone),
            recommendation="Reinstallare i pacchetti interessati se i file servono: apt install --reinstall <pacchetto>.",
            source="debsums:missing",
            confidence=Confidence.LOW,
        ))

    if unreadable:
        findings.append(Finding(
            title="debsums: alcuni file non leggibili, controllo parziale",
            category="integrity",
            severity=Severity.INFO,
            description=(
                f"{unreadable} file non sono stati letti per mancanza di permessi: "
                "senza root il controllo è parziale."
            ),
            evidence=f"{unreadable} errori di permesso",
            recommendation="Configurare sudo senza password (NOPASSWD) per l'utente dell'assessment o usare root.",
            source="debsums:partial",
            confidence=Confidence.LOW,
        ))

    if not (sensitive or binaries or other or gone):
        notes = []
        if ignored:
            notes.append(f"{len(ignored)} in documentazione/traduzioni (ignorati)")
        if gone_other:
            notes.append(f"{len(gone_other)} file mancanti fuori dalle cartelle di sistema")
        findings.append(Finding(
            title="debsums: nessun file di sistema modificato",
            category="integrity",
            severity=Severity.INFO,
            description="I file dei pacchetti corrispondono ai checksum della distribuzione.",
            evidence="; ".join(notes)[:500],
            recommendation="Nessuna azione richiesta.",
            source="debsums:summary",
            confidence=Confidence.MEDIUM if unreadable else Confidence.HIGH,
        ))

    return findings
