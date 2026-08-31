"""Carry the grade and scoring-mode result shared by every report format.

The score object explains how findings were scored; it does not claim which
project files discovery inspected, which remains separate run context.
"""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.file_score import FileScore
from gruffpy.scoring.grade import Grade
from gruffpy.scoring.pillar_score import PillarScore


@dataclass(frozen=True, slots=True)
class ScoreReport:
    """Describe the calculated grade and the mode used to score findings.

    Reporters consume this value for score presentation while run metadata
    separately tells users when project-rule context may be incomplete.

    Attributes:
        composite: Overall grade for the run.
        pillars: Per-pillar score breakdown.
        top_offenders: Highest-penalty files in the run.
        complexity_distribution: Cyclomatic complexity bucket counts.
        scope: Existing serialized scoring mode, ``full-project`` or ``diff``;
            not a statement about discovery coverage.
        explanation: Human-readable scoring explanation.
    """

    composite: Grade
    pillars: tuple[PillarScore, ...]
    top_offenders: tuple[FileScore, ...]
    complexity_distribution: dict[str, int]
    scope: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the native score container used by report renderers.

        The container retains native grade objects, scoring scope, explanation,
        pillar rows, offender rows, and complexity buckets. The v3 machine
        adapter projects the canonical composite and offender shapes without
        recalculating a value.

        Returns:
            JSON-ready native score data.
        """
        return {
            "composite": self.composite.to_dict(),
            "scope": self.scope,
            "explanation": self.explanation,
            "pillars": [p.to_dict() for p in self.pillars],
            "topOffenders": [f.to_dict() for f in self.top_offenders],
            "complexityDistribution": dict(self.complexity_distribution),
        }
