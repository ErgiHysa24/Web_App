"""Parser for Lynis output.

Lynis produce output strutturato in sezioni. Le righe rilevanti sono:

    * Some suggestion text
    ! Some warning text
    Hardening index : 65 [########            ]
    Tests performed : 234

Inoltre linee con marker [ WARNING ] / [ SUGGESTION ] a fine riga.
"""
from __future__ import annotations
import re

from risk_assessor.models import Finding, Severity, Confidence

import re as _re_ansi
_ANSI_RE = _re_ansi.compile(r"\x1b\[[0-9;]*[A-Za-z]")


# Riga con "Hardening index : 65 [###...]"
_HARDENING_RE = re.compile(r"Hardening index\s*:\s*(\d+)")
_TESTS_RE = re.compile(r"Tests performed\s*:\s*(\d+)")
# TAG Lynis: [BOOT-5264], [SSH-7408], [LYNIS], [DEB-0280], ecc.
_TAG = r"\[[A-Z][A-Z0-9_-]*(?:-\d+)?\]"

# "* suggestion text [TAG-1234]" — DEVE terminare con un TAG
_SUGGESTION_RE = re.compile(rf"^\s*\*\s+(.+?)\s*{_TAG}\s*$")
# "! warning text [TAG-1234]" — DEVE terminare con un TAG
_WARNING_RE = re.compile(rf"^\s*!\s+(.+?)\s*{_TAG}\s*$")
# "[ WARNING ]" o "[ SUGGESTION ]" a fine riga
_MARKER_WARN_RE = re.compile(r"\[\s*WARNING\s*\]\s*$", re.IGNORECASE)
_MARKER_SUGG_RE = re.compile(r"\[\s*SUGGESTION\s*\]\s*$", re.IGNORECASE)


# Prefissi di righe spurie (rumore di Lynis)
_NOISE_PREFIXES = (
    "-",               # "! - Checking for a running..."
    "checking",        # controlli interni
    "running",         # "running Lynis process"
    "found one",       # "Found one or more..." (già gestito dal TAG)
    "hardening index", # non è un finding
    "tests performed",
    "please",
    "note:",
    "warning:",        # warning introduttivi, non veri finding
    "if you",
    "you are",
    "auditor:",
    "language:",
    "test category:",
    "test group:",
    "program version:",
    "operating system",
    "kernel version",
    "hardware platform",
    "hostname:",
    "profiles:",
    "log file:",
    "report file:",
    "report version:",
    "plugin directory:",
)


def _is_noise(text: str) -> bool:
    low = text.strip().lower()
    if not low:
        return True
    for pfx in _NOISE_PREFIXES:
        if low.startswith(pfx):
            return True
    # Righe molto corte sono spesso rumore
    if len(low) < 15:
        return True
    return False


def parse_lynis(text: str) -> list[Finding]:
    findings: list[Finding] = []
    suggestions: list[str] = []
    warnings: list[str] = []

    hardening: int | None = None
    tests_performed: int | None = None

    seen_tags: set[str] = set()

    for raw_line in text.splitlines():
        # rimuove escape ANSI (Lynis li emette anche con --no-colors)
        clean = _ANSI_RE.sub("", raw_line)
        line = clean.rstrip()
        if not line.strip():
            continue

        # Formato .dat di Lynis: "key=value"
        stripped_line = line.strip()
        if "=" in stripped_line and not stripped_line.startswith("[") and not stripped_line.startswith("#"):
            key, _, value = stripped_line.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if key == "hardening_index" and value.isdigit():
                try:
                    hardening = int(value)
                except ValueError:
                    pass
                continue
            if key.startswith("warning") and value:
                if value.lower() not in {w.lower() for w in warnings}:
                    warnings.append(value)
                continue
            if key.startswith("suggestion") and value:
                if value.lower() not in {s.lower() for s in suggestions}:
                    suggestions.append(value)
                continue

        # Deduplica per TAG: Lynis ripete la stessa suggestion più volte
        tag_match = re.search(_TAG, line)
        if tag_match:
            tag = tag_match.group(0)
            if tag in seen_tags:
                continue
            seen_tags.add(tag)

        m = _HARDENING_RE.search(line)
        if m:
            try:
                hardening = int(m.group(1))
            except ValueError:
                pass
            continue

        m = _TESTS_RE.search(line)
        if m:
            try:
                tests_performed = int(m.group(1))
            except ValueError:
                pass
            continue

        # Riga "! warning"
        m = _WARNING_RE.match(line)
        if m:
            body = m.group(1).strip()
            if _is_noise(body):
                continue
            if body.lower() not in {w.lower() for w in warnings}:
                warnings.append(body)
            continue

        # Riga "* suggestion"
        m = _SUGGESTION_RE.match(line)
        if m:
            body = m.group(1).strip()
            # ignora sotto-righe informative
            low = body.lower()
            if low.startswith(("article:", "website:", "http://", "https://")):
                continue
            if _is_noise(body):
                continue
            if body.lower() not in {s.lower() for s in suggestions}:
                suggestions.append(body)
            continue

        # Righe che terminano con marker [ WARNING ] o [ SUGGESTION ]
        stripped = line.strip()
        if _MARKER_WARN_RE.search(stripped):
            body = _MARKER_WARN_RE.sub("", stripped).strip(" -[]")
            if body and not _is_noise(body):
                if body.lower() not in {w.lower() for w in warnings}:
                    warnings.append(body)
        elif _MARKER_SUGG_RE.search(stripped):
            body = _MARKER_SUGG_RE.sub("", stripped).strip(" -[]")
            if body and not _is_noise(body):
                if body.lower() not in {s.lower() for s in suggestions}:
                    suggestions.append(body)

    # Warning -> MEDIUM (Lynis warning sono da investigare, non critici di per sé)
    for w in warnings:
        findings.append(Finding(
            title=f"Lynis warning: {w[:80]}",
            category="hardening",
            severity=Severity.MEDIUM,
            description=f"Lynis ha segnalato: {w}",
            evidence=w[:500],
            recommendation="Verificare la configurazione segnalata da Lynis.",
            source="lynis:warning",
            confidence=Confidence.MEDIUM,
        ))

    # Suggestions -> un unico finding aggregato per ridurre il rumore.
    # Lynis produce 30-50 suggestion su un sistema non-hardened; raggrupparle
    # mantiene il report leggibile.
    if suggestions:
        evidence = "\n".join(f"- {s}" for s in suggestions[:25])
        if len(suggestions) > 25:
            evidence += f"\n... e altre {len(suggestions) - 25} suggestion"
        findings.append(Finding(
            title=f"Lynis suggestion: {len(suggestions)} raccomandazioni di hardening",
            category="hardening",
            severity=Severity.LOW,
            description=(
                f"Lynis ha prodotto {len(suggestions)} raccomandazioni di hardening. "
                "Vedere evidence per l'elenco completo."
            ),
            evidence=evidence[:1500],
            recommendation="Revisionare le raccomandazioni e applicare quelle rilevanti.",
            source="lynis:suggestion",
            confidence=Confidence.MEDIUM,
        ))

    # Hardening index -> INFO con valutazione
    if hardening is not None:
        if hardening < 40:
            level = Severity.HIGH
            desc = "Lynis hardening index basso."
        elif hardening < 60:
            level = Severity.MEDIUM
            desc = "Lynis hardening index nella media."
        elif hardening < 80:
            level = Severity.LOW
            desc = "Lynis hardening index buono."
        else:
            level = Severity.INFO
            desc = "Lynis hardening index eccellente."
        extra = f" (Tests performed: {tests_performed})" if tests_performed is not None else ""
        findings.append(Finding(
            title=f"Lynis hardening index: {hardening}/100",
            category="hardening",
            severity=level,
            description=desc + extra,
            evidence=f"Hardening index : {hardening}{extra}",
            recommendation="Migliorare i warning e suggestion di Lynis.",
            source="lynis:hardening-index",
            confidence=Confidence.HIGH,
        ))

    # Un audit completo stampa sempre l'hardening index: se manca e non c'è nient'altro,
    # Lynis non è partito o si è interrotto. Non è un "nessun problema".
    if not findings and hardening is None:
        return [Finding(
            title="Lynis: audit non completato",
            category="hardening",
            severity=Severity.INFO,
            description=("L'output di Lynis non contiene l'esito di un audit: l'assenza di "
                         "segnalazioni NON significa che il sistema sia a posto."),
            evidence=" | ".join(ln.strip() for ln in text.strip().splitlines()[-3:])[:500],
            recommendation="Eseguire 'lynis audit system' a mano sul sistema per vedere l'errore.",
            source="lynis:failed",
            confidence=Confidence.LOW,
        )]

    # Segnalazioni presenti ma senza hardening index: l'audit si è interrotto a metà.
    if findings and hardening is None:
        findings.append(Finding(
            title="Lynis: audit incompleto",
            category="hardening",
            severity=Severity.INFO,
            description=("Lynis ha prodotto alcune segnalazioni ma non l'hardening index finale: "
                         "l'audit si è probabilmente interrotto e altri controlli possono mancare."),
            evidence=" | ".join(ln.strip() for ln in text.strip().splitlines()[-3:])[:500],
            recommendation="Eseguire 'lynis audit system' a mano per completare l'audit.",
            source="lynis:partial",
            confidence=Confidence.LOW,
        ))

    # Summary
    if not findings:
        findings.append(Finding(
            title="Lynis: 0 segnalazioni",
            category="hardening",
            severity=Severity.INFO,
            description="Lynis non ha prodotto warning o suggestion.",
            evidence="Nessuna riga riconosciuta nell'output.",
            recommendation="Nessuna azione richiesta.",
            source="lynis:summary",
            confidence=Confidence.MEDIUM,
        ))
    else:
        findings.append(Finding(
            title=f"Lynis: {len(warnings)} warning, {len(suggestions)} suggestion",
            category="hardening",
            severity=Severity.INFO,
            description="Riepilogo dei finding prodotti da Lynis.",
            evidence=f"warnings={len(warnings)}, suggestions={len(suggestions)}, hardening={hardening}",
            recommendation="Verificare i warning e le suggestion più rilevanti.",
            source="lynis:summary",
            confidence=Confidence.MEDIUM,
        ))

    return findings
