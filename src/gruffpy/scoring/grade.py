"""Combine a numeric analysis score with its letter grade.

Reports use these helpers to present severity-weighted scores consistently.
The grade bands apply after the raw score is bounded and rounded.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal


@dataclass(frozen=True, slots=True)
class Grade:
    """Hold a normalised analysis score and the letter shown alongside it.

    Use `from_score` when converting a raw numeric score for a report.
    Use `letter` when only the grade label is needed.
    """

    score: float
    letter: str

    @classmethod
    def from_score(cls, score: float) -> "Grade":
        """Prepare the numeric score and letter displayed in a scan report.
        Bound the score before rounding so even an unusually large raw score can be shown safely.

        Args:
            score: Raw score before clamping and rounding.

        Returns:
            Grade with score clamped to 0 through 100 and rounded to two decimals.
        """
        normalised = _round_half_up(max(0.0, min(100.0, score)))
        return cls(score=normalised, letter=cls.letter_for(normalised))

    @staticmethod
    def letter_for(score: float) -> str:
        """Return the letter band for a normalized score.

        Args:
            score: Numeric score to map into a grade band.

        Returns:
            The letter grade for the score: A, B, C, D or F.
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

    Half-up rounding makes 53.125 become 53.13 instead of the 53.12 produced by Python's ties-to-even rounding.

    Args:
        score: Raw score before rounding.

    Returns:
        The score at two decimal places, with exact halves rounded away from zero.
    """
    return float(Decimal(repr(score)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
