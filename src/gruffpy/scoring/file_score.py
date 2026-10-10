"""Per-file score summary used by the top-offenders section of a report."""

from dataclasses import dataclass
from typing import Any

from gruffpy.scoring.grade import Grade


@dataclass(frozen=True, slots=True)
class FileScore:
    """Per-file score row used to populate the top-offenders table in a report.

    Attributes:
        file_path: Display path for the scored file.
        grade: Letter grade assigned to the file, ``None`` when the run evaluated nothing.
        findings: Total findings for the file.
        advisories: Advisory findings for the file.
        warnings: Warning findings for the file.
        errors: Error findings for the file.
        penalty: Score penalty before output rounding.
        max_cyclomatic: Maximum cyclomatic complexity observed in the file.
        max_cognitive: Maximum cognitive complexity observed in the file.
        max_lines: Maximum function length observed in the file.
        mutation_score: Optional mutation score for the file.
    """

    file_path: str
    grade: Grade | None
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
        """Serialize the native per-file score row.

        `penalty` is rounded to two decimals so PHP and Python comparisons
        remain stable. The v3 machine adapter normalizes the offender path and
        optional fields.

        Returns:
            JSON-ready native score fields and metric maxima.
        """
        return {
            "file": self.file_path,
            "grade": None if self.grade is None else self.grade.to_dict(),
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
