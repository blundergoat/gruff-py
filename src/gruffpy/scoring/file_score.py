"""Per-file score summary used by the top-offenders section of a report."""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.grade import Grade


@dataclass(frozen=True, slots=True)
class FileScore:
    file_path: str
    grade: Grade
    findings: int
    advisories: int
    warnings: int
    errors: int
    penalty: float
    max_cyclomatic: int | None = None
    max_cognitive: int | None = None
    max_lines: int | None = None
    mutation_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise the file score to its ``gruff-py.analysis.v1`` payload shape.

        ``penalty`` is rounded to two decimals so JSON comparisons across
        the PHP/Python implementations stay stable.

        Returns:
            JSON-ready dict with file path, grade, severity counts, and metric maxima.
        """
        return {
            "file": self.file_path,
            "grade": self.grade.to_dict(),
            "findings": self.findings,
            "advisories": self.advisories,
            "warnings": self.warnings,
            "errors": self.errors,
            "penalty": round(self.penalty, 2),
            "maxCyclomatic": self.max_cyclomatic,
            "maxCognitive": self.max_cognitive,
            "maxLines": self.max_lines,
            "mutationScore": self.mutation_score,
        }
