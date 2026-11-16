"""Console summary renderer.

Stampa a video un riepilogo colorato dell'assessment.
Usa solo ANSI escape (nessuna dipendenza).
Rileva se stdout è un TTY: se no, disattiva i colori.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

from risk_assessor.models import Assessment
from risk_assessor.risk.matrix import PROBABILITY_LABEL, max_risk, sort_by_risk


# ANSI colors
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_FG = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH": "\033[31m",      # red
    "MEDIUM": "\033[33m",    # yellow
    "LOW": "\033[36m",       # cyan
    "INFO": "\033[37m",      # white/grey
    "GREEN": "\033[32m",
}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


class _C:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{_RESET}"


def render_console_summary(
    assessment: Assessment,
    report_paths: list[Path],
    stream=None,
    top_n: int = 10,
) -> None:
    """Stampa il riepilogo colorato dell'assessment."""
    stream = stream or sys.stdout
    color = _C(_supports_color() and stream.isatty())

    def line(s: str = "") -> None:
        print(s, file=stream)

    width = 60
    bar = "═" * width

    line()
    line(color(_BOLD, bar))
    line(color(_BOLD, "  RISK ASSESSMENT COMPLETATO".center(width)))
    line(color(_BOLD, bar))
    line()

    line(f"  Target:   {color(_BOLD, assessment.target)}")
    line(f"  Modalità: {assessment.mode}")
    if assessment.system_label():
        line(f"  Sistema:  {assessment.system_label()}")
    line()

    # Risk level con colore
    level = assessment.risk_level
    level_color = _FG.get(level, "")
    score_bar = _score_bar(assessment.risk_score)
    line(f"  ▸ Livello:       {color(level_color + _BOLD, level)}  "
         f"{color(_DIM, '(dalla severità più alta trovata)')}")
    line(f"  ▸ Punteggio:     {color(level_color + _BOLD, f'{assessment.risk_score}/100')}  {score_bar}")
    mr_value, mr_level = max_risk(assessment.findings)
    line(f"  ▸ Rischio max:   {color(_FG.get(mr_level, '') + _BOLD, f'{mr_level} {mr_value}/12')}  "
         f"{color(_DIM, '(impatto x probabilità del finding peggiore)')}")
    line()

    # Counts
    counts = assessment.counts_by_severity()
    total = len(assessment.findings)
    line(color(_BOLD, "  Finding per severità:"))
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts[sev]
        sev_color = _FG.get(sev, "")
        icon = _icon(sev)
        label = color(sev_color, f"{icon} {sev:<9}")
        line(f"    {label}  {n}")
    line(f"    {' ' * 12}  {color(_DIM, f'({total} in totale)')}")
    line()

    # Tabella del rischio: rischio = impatto x probabilità
    if assessment.findings:
        line(color(_BOLD, "  Rischio = impatto x probabilità (primi " + str(top_n) + "):"))
        line(color(_DIM, f"    {'RISCHIO':<12}{'IMPATTO':<9}{'PROBAB.':<9}FINDING"))
        for f in _top(assessment.findings, top_n):
            lvl = f.risk_level
            tag = color(_FG.get(lvl, ""), f"{lvl:<8}{f.risk:>2}  ")
            title = f.title if len(f.title) <= 42 else f.title[:39] + "..."
            prob = PROBABILITY_LABEL.get(f.probability, "")
            line(f"    {tag}{f.impact:^7}  {prob:<8} {title}")
        if len(assessment.findings) > top_n:
            remaining = len(assessment.findings) - top_n
            line(f"    {color(_DIM, f'... e altri {remaining}')}")
        line()

    cmp = assessment.metadata.get("comparison")
    if isinstance(cmp, dict):
        render_comparison(cmp, stream, color)

    # Controlli non completati: senza, "pochi problemi" potrebbe voler dire "pochi controlli".
    if assessment.errors:
        line(color(_FG.get("MEDIUM", "") + _BOLD,
                   f"  ! Controlli non completati: {len(assessment.errors)}"))
        for e in assessment.errors[:8]:
            text = e if len(e) <= 70 else e[:67] + "..."
            line(f"    {color(_DIM, '-')} {text}")
        if len(assessment.errors) > 8:
            line(f"    {color(_DIM, f'... e altri {len(assessment.errors) - 8} (vedi il report)')}")
        line()
    skipped = assessment.not_applicable()
    if skipped:
        line(color(_DIM, f"  Non applicabili a questo sistema: {', '.join(sorted(skipped))}"))
        line()

    # Report paths
    if report_paths:
        line(color(_BOLD, "  Report:"))
        for p in report_paths:
            line(f"    {color(_DIM, str(p))}")
        line()

    line(color(_BOLD, bar))
    line()


def render_comparison(cmp: dict, stream=None, color=None) -> None:
    """Blocco "rispetto alla scansione precedente" (usato anche da `risk_assessor compare`)."""
    stream = stream or sys.stdout
    color = color or _C(_supports_color() and stream.isatty())

    def line(s: str = "") -> None:
        print(s, file=stream)

    line(color(_BOLD, f"  Rispetto alla scansione del {cmp.get('previous_date', '?')}:"))
    if cmp.get("delta") is not None:
        d = int(cmp["delta"])
        code = _FG.get("CRITICAL", "") if d > 0 else (_FG.get("LOW", "") if d < 0 else _DIM)
        trend = f"{d:+d} ({cmp.get('trend', '')})"
        line(f"    Punteggio {cmp.get('previous_score')} → {cmp.get('current_score')}  "
             f"{color(code + _BOLD, trend)}")
    new, resolved = cmp.get("new") or [], cmp.get("resolved") or []
    line(f"    Nuovi: {len(new)}   Risolti: {len(resolved)}   Ancora presenti: {cmp.get('unchanged', 0)}")
    unchecked = cmp.get("not_rechecked") or []
    if unchecked:
        line(color(_DIM, f"    Non ricontrollati (controllo non eseguito questa volta): {len(unchecked)}"))
    for label, rows in (("+", new), ("-", resolved)):
        for r in rows[:5]:
            title = str(r.get("title", ""))
            title = title if len(title) <= 50 else title[:47] + "..."
            sev = str(r.get("severity", "INFO"))
            line(f"    {label} {color(_FG.get(sev, ''), f'{sev:<8}')} {title}")
        if len(rows) > 5:
            line(f"    {color(_DIM, f'  ... e altri {len(rows) - 5}')}")
    line()


def _icon(sev: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }.get(sev, " ")


def _score_bar(score: int, width: int = 20) -> str:
    """Barra ASCII 0-100."""
    filled = max(0, min(width, round(score / 100 * width)))
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _top(findings, n: int):
    return sort_by_risk(findings)[:n]
