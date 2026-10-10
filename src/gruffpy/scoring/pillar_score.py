"""Score and finding counts aggregated to a single pillar (size, complexity, ...)."""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.grade import Grade


@dataclass(frozen=True, slots=True)
class PillarScore:
    """Per-pillar grade and severity counts contributing to the composite score.

    Attributes:
        pillar: Pillar name being scored.
        applicable: Whether the pillar applies to the analysed scope.
        grade: Letter grade for the pillar, or None when not applicable.
        findings: Total findings for the pillar.
        advisories: Advisory findings for the pillar.
        warnings: Warning findings for the pillar.
        errors: Error findings for the pillar.
        penalty: Score penalty before output rounding.
    """

    pillar: str
    applicable: bool
    grade: Grade | None
    findings: int
    advisories: int
    warnings: int
    errors: int
    penalty: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize the native per-pillar score row.

        `grade` is `None` when the pillar does not apply, and `penalty`
        is rounded to two decimals. The v3 machine adapter omits unavailable
        optional grade data.

        Returns:
            JSON-ready native pillar fields and severity counts.
        """
        return {
            "pillar": self.pillar,
            "applicable": self.applicable,
            "grade": self.grade.to_dict() if self.grade is not None else None,
            "findings": self.findings,
            "advisories": self.advisories,
            "warnings": self.warnings,
            "errors": self.errors,
            "penalty": round(self.penalty, 2),
        }
