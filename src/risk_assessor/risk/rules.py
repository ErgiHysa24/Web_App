"""Risk rules loader.

Carica rules/risk_rules.yaml. Se il file manca o è invalido,
ritorna i default hardcoded (stessi valori di engine.py).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from risk_assessor.models import Severity


DEFAULT_RULES_PATH = Path("rules/risk_rules.yaml")


@dataclass
class RiskRules:
    """Configurazione dello scoring, con default sensati."""

    severity_points: dict[Severity, int] = field(default_factory=lambda: {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 3,
        Severity.HIGH: 7,
        Severity.CRITICAL: 10,
    })

    caps: dict[Severity, int | None] = field(default_factory=lambda: {
        Severity.LOW: 10,
        Severity.MEDIUM: 30,
        Severity.HIGH: 50,
        Severity.CRITICAL: None,
    })

    # Tetto di punti per ORIGINE del finding (prefisso di `source`). Serve per i tool che
    # producono molti finding (Trivy: uno per pacchetto) e altrimenti saturerebbero il punteggio.
    source_caps: dict[str, int] = field(default_factory=lambda: {"trivy:package": 30, "debsecan:package": 30})

    multiplier: int = 2
    max_score: int = 100
    level_from: str = "highest_severity"

    score_thresholds: dict[str, tuple[int, int]] = field(default_factory=lambda: {
        "LOW": (0, 30),
        "MEDIUM": (31, 60),
        "HIGH": (61, 85),
        "CRITICAL": (86, 100),
    })


def load_rules(path: Path | str | None = None) -> RiskRules:
    """Carica le regole dal file YAML. Fallback ai default se mancante/invalido."""
    path = Path(path) if path else DEFAULT_RULES_PATH
    if not path.exists():
        return RiskRules()

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except (yaml.YAMLError, OSError):
        return RiskRules()

    if not isinstance(raw, dict):
        return RiskRules()

    return _parse(raw)


def _parse(raw: dict) -> RiskRules:
    rules = RiskRules()

    # severity_points
    sp = raw.get("severity_points")
    if isinstance(sp, dict):
        parsed = {}
        for name, value in sp.items():
            sev = _parse_severity(name)
            if sev is not None:
                try:
                    parsed[sev] = int(value)
                except (TypeError, ValueError):
                    pass
        if parsed:
            rules.severity_points = parsed

    # caps
    caps = raw.get("caps")
    if isinstance(caps, dict):
        parsed_caps: dict[Severity, int | None] = {}
        for name, value in caps.items():
            sev = _parse_severity(name)
            if sev is None:
                continue
            if value is None:
                parsed_caps[sev] = None
            else:
                try:
                    parsed_caps[sev] = int(value)
                except (TypeError, ValueError):
                    pass
        if parsed_caps:
            rules.caps = parsed_caps

    # source_caps
    sc = raw.get("source_caps")
    if isinstance(sc, dict):
        parsed_sc: dict[str, int] = {}
        for name, value in sc.items():
            try:
                if isinstance(name, str) and name and int(value) >= 0:
                    parsed_sc[name] = int(value)
            except (TypeError, ValueError):
                pass
        rules.source_caps = parsed_sc

    # scalari
    if isinstance(raw.get("multiplier"), (int, float)):
        rules.multiplier = int(raw["multiplier"])
    if isinstance(raw.get("max_score"), int):
        rules.max_score = raw["max_score"]
    if isinstance(raw.get("level_from"), str):
        rules.level_from = raw["level_from"]

    # soglie
    st = raw.get("score_thresholds")
    if isinstance(st, dict):
        parsed_st = {}
        for name, value in st.items():
            if (isinstance(value, (list, tuple)) and len(value) == 2):
                try:
                    parsed_st[name] = (int(value[0]), int(value[1]))
                except (TypeError, ValueError):
                    pass
        if parsed_st:
            rules.score_thresholds = parsed_st

    return rules


def _parse_severity(name: str) -> Severity | None:
    try:
        return Severity(name.strip().upper())
    except (ValueError, AttributeError):
        return None
