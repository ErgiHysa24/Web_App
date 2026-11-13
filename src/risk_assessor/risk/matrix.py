"""Matrice del rischio: rischio = impatto x probabilità.

- **Impatto** = gravità del finding (quanto danno fa se il problema è reale):
  INFO 0, LOW 1, MEDIUM 2, HIGH 3, CRITICAL 4.
- **Probabilità** = quanto è probabile che il problema sia reale e sfruttabile, stimata dalla
  confidenza del rilevamento: LOW 1 (indicativo), MEDIUM 2 (probabile), HIGH 3 (certo).
- **Rischio** = impatto x probabilità (0-12), tradotto in un livello con fasce fisse.

Funzioni pure e deterministiche: stessi finding, stessa matrice. Il punteggio globale 0-100
(risk/engine.py) resta separato e non dipende da questa matrice.
"""
from __future__ import annotations

from risk_assessor.models import Confidence, Finding, Severity

IMPACT: dict[Severity, int] = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4,
}
PROBABILITY: dict[Confidence, int] = {
    Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3,
}
IMPACT_LABEL = {0: "nullo", 1: "basso", 2: "medio", 3: "alto", 4: "critico"}
PROBABILITY_LABEL = {1: "bassa", 2: "media", 3: "alta"}

# (soglia minima, livello): la prima fascia con soglia <= rischio vince.
BANDS: tuple[tuple[int, str], ...] = (
    (12, "CRITICAL"), (8, "HIGH"), (4, "MEDIUM"), (1, "LOW"), (0, "INFO"),
)
LEVEL_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def impact(f: Finding) -> int:
    return IMPACT.get(f.severity, 0)


def probability(f: Finding) -> int:
    return PROBABILITY.get(f.confidence, 2)


def risk(f: Finding) -> int:
    return impact(f) * probability(f)


def max_risk(findings: list[Finding]) -> tuple[int, str]:
    """Rischio più alto tra i finding (valore, livello); (0, "INFO") se non ce ne sono."""
    value = max((risk(f) for f in findings), default=0)
    return value, risk_level(value)


def risk_level(value: int) -> str:
    for threshold, level in BANDS:
        if value >= threshold:
            return level
    return "INFO"


def sort_by_risk(findings: list[Finding]) -> list[Finding]:
    """Dal rischio più alto al più basso; a parità, gravità e poi titolo."""
    return sorted(findings, key=lambda f: (-risk(f), -impact(f), f.title))


def grid(findings: list[Finding]) -> dict[tuple[int, int], int]:
    """Conteggio dei finding per cella (impatto, probabilità); gli INFO sono esclusi."""
    cells: dict[tuple[int, int], int] = {}
    for f in findings:
        if impact(f) == 0:
            continue
        key = (impact(f), probability(f))
        cells[key] = cells.get(key, 0) + 1
    return cells


def counts_by_level(findings: list[Finding]) -> dict[str, int]:
    out = {lvl: 0 for lvl in LEVEL_ORDER}
    for f in findings:
        out[risk_level(risk(f))] += 1
    return out
