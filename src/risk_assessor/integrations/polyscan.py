"""Import dei rapporti JSON di polyscan (`polyscan scan|dast --json`) nell'assessment.

WatchDog controlla il sistema; polyscan controlla il codice e le applicazioni che ci
girano sopra (SAST, segreti, librerie vulnerabili, configurazione dei container, sito in
esecuzione). Importando i suoi rapporti, il risk assessment di un server include anche le
applicazioni che ospita, con un solo punteggio e un solo report.

- Lo stesso problema in più file (stesso strumento e stessa regola) diventa un solo
  finding con l'elenco dei punti.
- Uno strumento di polyscan in errore o non installato compare tra i controlli non
  completati: l'assenza di segnalazioni da quello strumento non vuol dire "pulito".
- Il file arriva da fuori: ogni campo è controllato e trattato come testo non fidato.
"""
from __future__ import annotations

import json
from pathlib import Path

from risk_assessor.models import Confidence, Finding, Severity

MAX_REPORT_BYTES = 50 * 1024 * 1024
_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
             "low": Severity.LOW, "info": Severity.INFO}
# categoria di polyscan -> (categoria WatchDog, etichetta, cosa fare)
_KIND = {
    "code": ("application", "codice", "Correggere il codice indicato (vedi la regola dello strumento)."),
    "secret": ("secrets", "segreto", "Revocare e sostituire il segreto, poi toglierlo dal codice e dalla cronologia git."),
    "dependency": ("dependencies", "libreria", "Aggiornare la libreria a una versione corretta."),
    "config": ("app-config", "configurazione", "Correggere la configurazione indicata."),
    "runtime": ("web", "sito", "Correggere la risposta del sito (intestazioni, cookie, pagine esposte)."),
}
_MAX_LOCATIONS = 12


class PolyscanReportError(ValueError):
    """Il file non è un rapporto JSON di polyscan valido."""


def _load(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise PolyscanReportError(f"{path}: file troppo grande per un rapporto di polyscan")
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise PolyscanReportError(f"{path}: non leggibile ({e.strerror or e})") from None
    except json.JSONDecodeError:
        raise PolyscanReportError(f"{path}: non è un file JSON") from None
    if not isinstance(data, dict) or "polyscan" not in data or not isinstance(data.get("findings"), list):
        raise PolyscanReportError(f"{path}: non è un rapporto JSON di polyscan (crealo con --json)")
    return data


def import_report(path: str | Path) -> tuple[list[Finding], list[str], str]:
    """Finding, controlli non completati e descrizione dell'origine di un rapporto polyscan."""
    p = Path(path)
    data = _load(p)
    root = str(data.get("root", "")) or p.name
    kind = str(data.get("kind", "folder"))
    origin = f"polyscan {str(data.get('polyscan', ''))[:20]} su {'sito ' if kind == 'url' else ''}{root}"[:200]

    groups: dict[tuple[str, str], dict] = {}
    for i, item in enumerate(data["findings"], 1):
        if not isinstance(item, dict):
            raise PolyscanReportError(f"{path}: il finding numero {i} non è valido")
        sev = _SEVERITY.get(str(item.get("severity", "")).lower())
        tool = str(item.get("tool", "")).strip()
        if sev is None or not tool:
            raise PolyscanReportError(f"{path}: il finding numero {i} non è valido")
        rule = str(item.get("rule", "")).strip() or str(item.get("message", ""))[:60]
        g = groups.setdefault((tool, rule), {"severity": sev, "items": [], "tool": tool, "rule": rule,
                                             "category": str(item.get("category", "code")),
                                             "message": str(item.get("message", "")),
                                             "cwe": str(item.get("cwe", ""))[:200]})
        if list(_SEVERITY.values()).index(sev) < list(_SEVERITY.values()).index(g["severity"]):
            g["severity"] = sev
        loc = str(item.get("file", ""))
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if loc:
            g["items"].append(f"{loc}:{line}" if line else loc)

    findings = []
    for g in groups.values():
        cat, label, reco = _KIND.get(g["category"], _KIND["code"])
        places = list(dict.fromkeys(g["items"]))
        where = f" ({len(places)} punti)" if len(places) > 1 else ""
        evidence = [f"Regola: {g['rule']}"] + ([f"CWE: {g['cwe']}"] if g["cwe"] else [])
        evidence += places[:_MAX_LOCATIONS]
        if len(places) > _MAX_LOCATIONS:
            evidence.append(f"… e altri {len(places) - _MAX_LOCATIONS} punti")
        findings.append(Finding(
            title=f"{g['tool']} ({label}): {g['message'][:90]}{where}",
            category=cat, severity=g["severity"],
            description=f"{g['message']} Rilevato da {g['tool']} tramite {origin}.",
            evidence="\n".join(evidence)[:1500], recommendation=reco,
            source=f"polyscan:{g['category']}", confidence=Confidence.MEDIUM,
        ))

    errors = []
    for t in data.get("tools") or []:
        if not isinstance(t, dict):
            continue
        status = str(t.get("status", ""))
        if status in ("error", "unavailable"):
            what = "in errore" if status == "error" else "non disponibile"
            detail = str(t.get("detail", ""))[:150]
            errors.append(f"polyscan/{str(t.get('name', '?'))[:40]}: {what}" + (f" ({detail})" if detail else ""))
    return findings, errors, origin
