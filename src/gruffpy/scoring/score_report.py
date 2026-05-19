"""Composite ``ScoreReport`` carrying the grade, pillars, top offenders, and metrics."""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.file_score import FileScore
from gruffpy.scoring.grade import Grade
from gruffpy.scoring.pillar_score import PillarScore


@dataclass(frozen=True, slots=True)
class ScoreReport:
    composite: Grade
    pillars: tuple[PillarScore, ...]
    top_offenders: tuple[FileScore, ...]
    complexity_distribution: dict[str, int]
    scope: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full score report to its ``gruff-py.analysis.v1`` payload shape.

        Composite grade, scope, explanation string, all pillar scores, the
        top-offender table, and the cyclomatic-complexity distribution
        buckets each appear under their schema-specified camelCase keys.

        Returns:
            JSON-ready dict matching the cross-implementation schema.
        """
        return {
            "composite": self.composite.to_dict(),
            "scope": self.scope,
            "explanation": self.explanation,
            "pillars": [p.to_dict() for p in self.pillars],
            "topOffenders": [f.to_dict() for f in self.top_offenders],
            "complexityDistribution": dict(self.complexity_distribution),
        }
