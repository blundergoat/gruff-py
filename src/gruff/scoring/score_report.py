"""Composite ``ScoreReport`` carrying the grade, pillars, top offenders, and metrics."""

from dataclasses import dataclass
from typing import Any

from gruff.scoring.file_score import FileScore
from gruff.scoring.grade import Grade
from gruff.scoring.pillar_score import PillarScore


@dataclass(frozen=True, slots=True)
class ScoreReport:
    composite: Grade
    pillars: tuple[PillarScore, ...]
    top_offenders: tuple[FileScore, ...]
    complexity_distribution: dict[str, int]
    scope: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "composite": self.composite.to_dict(),
            "scope": self.scope,
            "explanation": self.explanation,
            "pillars": [p.to_dict() for p in self.pillars],
            "topOffenders": [f.to_dict() for f in self.top_offenders],
            "complexityDistribution": dict(self.complexity_distribution),
        }
