"""Score and finding counts aggregated to a single pillar (size, complexity, ...)."""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.grade import Grade


@dataclass(frozen=True, slots=True)
class PillarScore:
    """Per-pillar grade + severity counts contributing to the composite score."""

    pillar: str
    applicable: bool
    grade: Grade | None
    findings: int
    advisories: int
    warnings: int
    errors: int
    penalty: float

    def to_dict(self) -> dict[str, Any]:
        """Serialise the pillar score to its ``gruff-py.analysis.v1`` payload shape.

        ``grade`` becomes ``None`` (not the literal ``"n/a"``) when the
        pillar is not applicable; reporters render the human-friendly form.
        ``penalty`` is rounded to two decimals to match gruff-php.

        Returns:
            JSON-ready dict with pillar name, applicability, grade, and severity counts.
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
