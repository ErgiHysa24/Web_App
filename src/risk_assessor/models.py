"""Data models for Linux Risk Assessor."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from risk_assessor.sanitize import clean_text


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Finding:
    title: str
    category: str
    severity: Severity
    description: str
    evidence: str
    recommendation: str
    source: str
    confidence: Confidence = Confidence.MEDIUM
    # Comando di rimedio opzionale (mostrato nel report HTML con avviso di verifica).
    command: str = ""

    def __post_init__(self) -> None:
        # Questi campi contengono testo scritto dal target: niente escape del terminale.
        for name in ("title", "description", "evidence", "recommendation", "command"):
            value = getattr(self, name)
            if isinstance(value, str):
                setattr(self, name, clean_text(value))

    # Rischio = impatto x probabilità (vedi risk/matrix.py)
    @property
    def impact(self) -> int:
        from risk_assessor.risk.matrix import impact
        return impact(self)

    @property
    def probability(self) -> int:
        from risk_assessor.risk.matrix import probability
        return probability(self)

    @property
    def risk(self) -> int:
        return self.impact * self.probability

    @property
    def risk_level(self) -> str:
        from risk_assessor.risk.matrix import risk_level
        return risk_level(self.risk)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["impact"] = self.impact
        d["probability"] = self.probability
        d["risk"] = self.risk
        d["risk_level"] = self.risk_level
        from risk_assessor.risk.compliance import controls_for
        d["compliance"] = {fw: list(ids) for fw, ids in controls_for(self).items()}
        from risk_assessor.risk.attack import techniques_for
        d["attack"] = list(techniques_for(self))
        return d


@dataclass
class Assessment:
    target: str
    mode: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cleanup_status: str = "NOT_RUN"
    metadata: dict[str, Any] = field(default_factory=dict)
    # Computed at finish()
    risk_score: int = 0
    risk_level: str = "LOW"

    def __post_init__(self) -> None:
        # il target può essere l'hostname riportato dal sistema remoto
        if isinstance(self.target, str):
            self.target = clean_text(self.target)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def finish(self) -> None:
        # Local import to avoid circular dependency with risk.engine
        from risk_assessor.risk.engine import calculate_risk
        result = calculate_risk(self.findings)
        self.risk_score = result.score
        self.risk_level = result.level.value
        self.finished_at = datetime.now(timezone.utc)

    def system_label(self) -> str:
        """"Ubuntu 24.04.5 LTS · apt · systemd" (vuoto se il sistema non è stato rilevato)."""
        host = self.metadata.get("host") or {}
        name = host.get("name") or ""
        if not name or name == "unknown":
            return ""
        parts = [name]
        if host.get("package_manager"):
            parts.append(str(host["package_manager"]))
        if host.get("init") and host["init"] != "unknown":
            parts.append(str(host["init"]))
        if host.get("container"):
            parts.append(f"container {host['container']}")
        return clean_text(" · ".join(parts))

    def not_applicable(self) -> dict[str, str]:
        """Controlli richiesti che non hanno senso su questo sistema, con il motivo."""
        return dict(self.metadata.get("not_applicable") or {})

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def risk_matrix(self) -> dict:
        """Finding per livello di rischio (impatto x probabilità) e per cella della matrice."""
        from risk_assessor.risk.matrix import counts_by_level, grid
        return {
            "by_level": counts_by_level(self.findings),
            "cells": [{"impact": i, "probability": p, "count": n}
                      for (i, p), n in sorted(grid(self.findings).items())],
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "risk": {
                "score": self.risk_score,
                "level": self.risk_level,
            },
            "counts": self.counts_by_severity(),
            "risk_matrix": self.risk_matrix(),
            "findings": [f.to_dict() for f in self.findings],
            "tools_used": self.tools_used,
            "errors": self.errors,
            "cleanup_status": self.cleanup_status,
            "metadata": self.metadata,
        }
