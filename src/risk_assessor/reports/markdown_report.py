"""Markdown report generator."""
from __future__ import annotations
from pathlib import Path

from risk_assessor.models import Assessment
from risk_assessor.risk.matrix import (
    LEVEL_ORDER, counts_by_level, grid, max_risk, sort_by_risk,
)
from risk_assessor.reports import private_dir, private_file
from risk_assessor.risk.areas import AREAS, control_of, group_by_area
from risk_assessor.risk.compliance import FRAMEWORKS, coverage, short_refs


_SEV_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🔵", "INFO": "⚪",
}


def generate_markdown_report(assessment: Assessment, output_dir: Path) -> Path:
    output_dir = private_dir(output_dir)
    out_file = output_dir / "assessment.md"
    out_file.write_text(_render(assessment), encoding="utf-8")
    return private_file(out_file)


def _render(a: Assessment) -> str:
    lines: list[str] = []
    lines.append("# Security Assessment Report")
    lines.append("")
    lines.append(f"**Obiettivo:** `{a.target}`  ")
    lines.append(f"**Modalità:** `{a.mode}`  ")
    if a.system_label():
        lines.append(f"**Sistema:** {_html_safe(a.system_label())}  ")
    lines.append(f"**Inizio:** {a.started_at.isoformat()}  ")
    if a.finished_at:
        lines.append(f"**Fine:** {a.finished_at.isoformat()}  ")
    lines.append("")
    lines.append("## Riepilogo")
    lines.append("")
    lines.append(f"**Rischio complessivo:** **{a.risk_level}** (punteggio **{a.risk_score}/100**; "
                 "il livello è la severità più alta trovata)  ")
    mr_value, mr_level = max_risk(a.findings)
    lines.append(f"**Rischio massimo (impatto × probabilità):** **{mr_level}** ({mr_value}/12)")
    lines.append("")
    lines.append("| Severità | Finding |")
    lines.append("|---|---|")
    counts = a.counts_by_severity()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {_SEV_EMOJI[sev]} {sev} | {counts[sev]} |")
    lines.append(f"| **Totale** | **{len(a.findings)}** |")
    lines.append("")
    lines.extend(_comparison_section(a))
    if a.findings:
        lines.extend(_risk_section(a))
        lines.extend(_areas_section(a))
        lines.extend(_compliance_section(a))
        lines.extend(_attack_section(a))
        lines.append("## Findings")
        lines.append("")
        lines.append("| Rischio | Impatto | Probabilità | Severità | Titolo | Categoria | Origine | Confidenza |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for f in _sorted_findings(a.findings):
            emoji = _SEV_EMOJI[f.severity.value]
            lines.append(
                f"| {f.risk_level} ({f.risk}) | {f.impact} | {f.probability} | "
                f"{emoji} {f.severity.value} | {_esc(f.title)} | "
                f"{_esc(f.category)} | `{_esc(f.source)}` | {f.confidence.value} |"
            )
        lines.append("")
        lines.append("## Dettaglio dei finding")
        lines.append("")
        for i, f in enumerate(_sorted_findings(a.findings), 1):
            emoji = _SEV_EMOJI[f.severity.value]
            lines.append(f"### {i}. {emoji} {_html_safe(f.title)}")
            lines.append("")
            lines.append(f"- **Rischio:** {f.risk_level} ({f.risk}) = impatto {f.impact} × probabilità {f.probability}")
            lines.append(f"- **Severità:** {f.severity.value}")
            lines.append(f"- **Categoria:** {f.category}")
            lines.append(f"- **Origine:** `{f.source}`")
            lines.append(f"- **Confidenza:** {f.confidence.value}")
            if short_refs(f):
                lines.append(f"- **Riferimenti:** {short_refs(f)}")
            lines.append("")
            lines.append(f"**Descrizione:** {_html_safe(f.description)}")
            lines.append("")
            if f.evidence:
                lines.append("**Evidenza:**")
                lines.append("")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
                lines.append("")
            lines.append(f"**Raccomandazione:** {_html_safe(f.recommendation)}")
            lines.append("")
    if a.errors:
        lines.append("## Controlli non completati o non eseguiti")
        lines.append("")
        lines.append("_Per questi controlli il risultato manca o è parziale: l'assenza di segnalazioni "
                     "non significa che vada tutto bene._")
        lines.append("")
        lines.extend(f"- {_md_line(e)}" for e in a.errors)
        lines.append("")
    if a.not_applicable():
        lines.append("## Non applicabili a questo sistema")
        lines.append("")
        lines.extend(f"- **{n}**: {_md_line(r)}" for n, r in sorted(a.not_applicable().items()))
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"_Report generato da WatchDog — controlli eseguiti: {', '.join(a.tools_used) or 'n/d'}_")
    lines.append("")
    return "\n".join(lines)


_IMPACT_IT = {1: "Basso", 2: "Medio", 3: "Alto", 4: "Critico"}


def _html_safe(text: str) -> str:
    """Testo che arriva dal target: niente HTML interpretato dai visualizzatori Markdown."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_line(text: str) -> str:
    """Una riga di testo (anche dal target) che non rompe l'elenco Markdown."""
    return _html_safe(" ".join(str(text).split())).replace("|", "\\|")


def _risk_section(a: Assessment) -> list[str]:
    """Matrice impatto x probabilità e conteggio per livello di rischio."""
    lines = ["## Rischio = impatto × probabilità", ""]
    lines.append("L'impatto è la gravità del finding (1 basso … 4 critico); la probabilità dice quanto è "
                 "probabile che il problema sia reale e sfruttabile, stimata dalla confidenza del "
                 "rilevamento (1 bassa, 2 media, 3 alta). Rischio = impatto × probabilità (0-12).")
    lines.append("")
    cells = grid(a.findings)
    lines.append("| Impatto \\ Probabilità | Bassa (1) | Media (2) | Alta (3) |")
    lines.append("|---|---|---|---|")
    for imp in (4, 3, 2, 1):
        row = [str(cells.get((imp, p), 0)) for p in (1, 2, 3)]
        lines.append(f"| {_IMPACT_IT[imp]} ({imp}) | " + " | ".join(row) + " |")
    lines.append("")
    by_level = counts_by_level(a.findings)
    lines.append("| Livello di rischio | Finding |")
    lines.append("|---|---|")
    for lvl in LEVEL_ORDER:
        lines.append(f"| {lvl} | {by_level[lvl]} |")
    lines.append("")
    return lines


def _compliance_section(a: Assessment) -> list[str]:
    lines: list[str] = []
    for fw, name in FRAMEWORKS.items():
        rows = coverage(a.findings, fw)
        if not rows:
            continue
        if not lines:
            lines += ["## Riferimenti normativi", "",
                      "_Controlli a cui si riferiscono i problemi trovati: un aiuto per l'audit, "
                      "non una dimostrazione di conformità._", ""]
        lines += [f"### {name}", "", "| Controllo | Titolo | Problemi | Più grave |", "|---|---|---|---|"]
        lines += [f"| {r['id']} | {r['title']} | {r['count']} | {r['worst']} |" for r in rows]
        lines.append("")
    return lines


_COV_MD = {"covered": "rilevata", "partial": "parziale", "none": "**NON rilevata**", "unknown": "non nel layer",
           "other-platform": "layer di altra piattaforma"}


def _attack_section(a: Assessment) -> list[str]:
    data = a.metadata.get("attack")
    if not isinstance(data, dict) or not data.get("techniques"):
        return []
    layer = data.get("layer")
    lines = [f"## Tecniche d'attacco (MITRE ATT&CK v{data.get('version', '')})", "",
             "_Tecniche che i problemi rendono possibili: giudizio di WatchDog, non una mappa ufficiale._"
             + (f" Copertura dal layer **{_md(str(layer))}**." if layer else ""), ""]
    head = "| ID | Tecnica | Problemi | Più grave |" + (" Rilevamento |" if layer else "")
    lines += [head, "|---|---|---|---|" + ("---|" if layer else "")]
    for r in data["techniques"]:
        lines.append(f"| {r['id']} | {_md(r['name'])} | {r['count']} | {r['worst']} |"
                     + (f" {_COV_MD.get(r.get('coverage'), '?')} |" if layer else ""))
    lines.append("")
    return lines


def _comparison_section(a: Assessment) -> list[str]:
    cmp = a.metadata.get("comparison")
    if not isinstance(cmp, dict):
        return []
    lines = ["## Rispetto alla scansione precedente", "",
             f"Confronto con `{_esc(str(cmp.get('previous_target', '')))}` del {_esc(str(cmp.get('previous_date', '')))}."
             " Contano solo i problemi (esclusi i finding informativi).", ""]
    if cmp.get("delta") is not None:
        lines.append(f"**Punteggio:** {cmp.get('previous_score')} → {cmp.get('current_score')} "
                     f"({int(cmp['delta']):+d}, {cmp.get('trend', '')})")
        lines.append("")
    for title, key in (("Nuovi", "new"), ("Risolti", "resolved")):
        rows = cmp.get(key) or []
        lines.append(f"**{title} ({len(rows)})**")
        lines.append("")
        lines.extend(f"- {_SEV_EMOJI.get(str(r.get('severity')), '')} {r.get('severity')} — {_md(str(r.get('title', '')))}"
                     for r in rows)
        if not rows:
            lines.append("- nessuno")
        lines.append("")
    lines.append(f"**Ancora presenti:** {cmp.get('unchanged', 0)}")
    lines.append("")
    unchecked = cmp.get("not_rechecked") or []
    if unchecked:
        lines.append(f"**Non ricontrollati ({len(unchecked)})** — il loro controllo questa volta non è stato eseguito:")
        lines.append("")
        lines.extend(f"- {r.get('severity')} — {_md(str(r.get('title', '')))}" for r in unchecked)
        lines.append("")
    return lines


def _md(text: str) -> str:
    return _html_safe(" ".join(text.split())).replace("|", "\\|")


_SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _areas_section(a: Assessment) -> list[str]:
    """Heatmap testuale: finding per macro-area e severità, poi per controllo in ogni area."""
    lines = ["## Aree (heatmap)", "",
             "| Area | " + " | ".join(f"{_SEV_EMOJI[s]} {s}" for s in _SEVS) + " | Totale |",
             "|---|" + "---|" * (len(_SEVS) + 1)]
    groups = group_by_area(a.findings)
    for area, fs in groups.items():
        counts = [sum(1 for f in fs if f.severity.value == s) for s in _SEVS]
        lines.append(f"| {AREAS[area][0]} | " + " | ".join(str(c) if c else "·" for c in counts)
                     + f" | {len(fs)} |")
    lines.append("")
    for area, fs in groups.items():
        lines.append(f"### {AREAS[area][0]}")
        lines.append("")
        lines.append("| Controllo | " + " | ".join(_SEVS) + " | Totale |")
        lines.append("|---|" + "---|" * (len(_SEVS) + 1))
        by_control: dict[str, list] = {}
        for f in fs:
            by_control.setdefault(control_of(f), []).append(f)
        for control, cf in sorted(by_control.items()):
            counts = [sum(1 for f in cf if f.severity.value == s) for s in _SEVS]
            lines.append(f"| {_esc(control)} | " + " | ".join(str(c) if c else "·" for c in counts)
                         + f" | {len(cf)} |")
        lines.append("")
    return lines


def _sorted_findings(findings):
    return sort_by_risk(findings)


def _esc(text: str) -> str:
    return _html_safe(text).replace("|", "\\|").replace("\n", " ")
