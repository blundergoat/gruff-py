"""Score and finding counts aggregated to a single pillar (size, complexity, ...)."""

from dataclasses import dataclass
from typing import Any

from gruff.scoring.grade import Grade


@dataclass(frozen=True, slots=True)
class PillarScore:
    pillar: str
    applicable: bool
    grade: Grade | None
    findings: int
    advisories: int
    warnings: int
    errors: int
    penalty: float

    def to_dict(self) -> dict[str, Any]:
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
