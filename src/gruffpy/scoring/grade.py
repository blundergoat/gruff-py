"""Numeric score paired with the letter grade derived from gruffpy's grade bands."""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal


@dataclass(frozen=True, slots=True)
class Grade:
    """Normalized numeric score paired with a letter grade."""

    score: float
    letter: str

    @classmethod
    def from_score(cls, score: float) -> "Grade":
        """Create a grade from a raw numeric score.

        Args:
            score: Raw score before clamping and rounding.

        Returns:
            Grade with score clamped to 0 through 100 and rounded to two decimals.
        """
        normalised = max(0.0, min(100.0, _round_half_up(score)))
        return cls(score=normalised, letter=cls.letter_for(normalised))

    @staticmethod
    def letter_for(score: float) -> str:
        """Return the letter band for a normalized score.

        Args:
            score: Numeric score to map into a grade band.

        Returns:
            Letter grade from A through F.
        """
        if score >= 90.0:
            return "A"
        if score >= 80.0:
            return "B"
        if score >= 70.0:
            return "C"
        if score >= 60.0:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, float | str]:
        """Serialize the grade to a JSON-compatible mapping.

        Returns:
            Dictionary containing the numeric score and letter grade.
        """
        return {"score": self.score, "grade": self.letter}


def _round_half_up(score: float) -> float:
    """Round one score to the ratified two decimals, breaking ties away from zero.

    Python's built-in ``round`` breaks ties to even, so 53.125 becomes 53.12 here while Go, PHP,
    Rust, and JavaScript all produce 53.13. The family contract fixes the precision but not the
    tie-break, and a scorer that disagrees with its four siblings on the last cent would fail the
    cross-port scoring gate for a reason that has nothing to do with the formula.

    Args:
        score: Raw score before rounding.

    Returns:
        The score at two decimal places, with exact halves rounded away from zero.
    """
    return float(Decimal(repr(score)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
