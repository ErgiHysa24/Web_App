"""Deterministic risk engine.

Maps findings to a numeric score (0-100) and a risk level.
This module has NO dependency on AI and is the authoritative
source of the security score.

Le regole di scoring sono caricate da rules/risk_rules.yaml (se presente).
Fallback ai default hardcoded se il file manca o è invalido.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

from risk_assessor.models import Finding, Severity
from risk_assessor.risk.rules import load_rules, RiskRules


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_LEVEL_ORDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: RiskLevel
    counts: dict[str, int]
    total_findings: int


def calculate_risk(
    findings: list[Finding],
    rules: RiskRules | None = None,
) -> RiskResult:
    """Compute risk score and level from findings.

    Deterministic: same input -> same output. No I/O, no AI.
    """
    if rules is None:
        rules = load_rules()

    counts = _count_by_severity(findings)
    total = len(findings)

    if total == 0:
        return RiskResult(score=0, level=RiskLevel.LOW, counts=counts, total_findings=0)

    score = _compute_score(findings, rules)
    level = _compute_level(findings, score, rules)

    return RiskResult(score=score, level=level, counts=counts, total_findings=total)


def _apply_source_caps(findings: list[Finding], rules: RiskRules) -> list[Finding]:
    """Per le origini con un tetto, conta solo i finding più gravi finché i punti non lo raggiungono.

    Il livello di rischio non cambia (dipende da tutti i finding): il tetto limita solo
    quanto un'unica origine può spingere il punteggio numerico.
    """
    if not rules.source_caps:
        return findings
    kept: list[Finding] = []
    capped: dict[str, list[Finding]] = {}
    for f in findings:
        prefix = next((p for p in rules.source_caps if f.source.startswith(p)), None)
        if prefix is None:
            kept.append(f)
        else:
            capped.setdefault(prefix, []).append(f)
    for prefix, group in capped.items():
        used = 0
        for f in sorted(group, key=lambda x: -rules.severity_points.get(x.severity, 0)):
            pts = rules.severity_points.get(f.severity, 0)
            if used + pts > rules.source_caps[prefix]:
                continue
            used += pts
            kept.append(f)
    return kept


def _compute_score(findings: list[Finding], rules: RiskRules) -> int:
    """Somma i punti con cap per categoria."""
    points_by_severity: dict[Severity, int] = {s: 0 for s in Severity}
    for f in _apply_source_caps(findings, rules):
        points_by_severity[f.severity] += rules.severity_points.get(f.severity, 0)

    total = 0
    for sev, raw_points in points_by_severity.items():
        cap = rules.caps.get(sev)
        if cap is not None:
            raw_points = min(raw_points, cap)
        total += raw_points

    score = total * rules.multiplier
    return min(score, rules.max_score)


def _compute_level(
    findings: list[Finding],
    score: int,
    rules: RiskRules,
) -> RiskLevel:
    if rules.level_from == "score_thresholds":
        return _level_from_score(score, rules.score_thresholds)
    # default: highest_severity
    highest = _highest_severity(findings)
    return _severity_to_level(highest)


def _level_from_score(score: int, thresholds: dict[str, tuple[int, int]]) -> RiskLevel:
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lo, hi = thresholds.get(name, (0, 100))
        if lo <= score <= hi:
            return RiskLevel(name)
    return RiskLevel.LOW


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _highest_severity(findings: list[Finding]) -> Severity:
    highest = Severity.INFO
    for f in findings:
        if _LEVEL_ORDER.index(f.severity) > _LEVEL_ORDER.index(highest):
            highest = f.severity
    return highest


def _severity_to_level(sev: Severity) -> RiskLevel:
    if sev == Severity.CRITICAL:
        return RiskLevel.CRITICAL
    if sev == Severity.HIGH:
        return RiskLevel.HIGH
    if sev == Severity.MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
