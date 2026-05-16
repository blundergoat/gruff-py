"""Numeric score paired with the letter grade derived from gruffpy's grade bands."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Grade:
    score: float
    letter: str

    @classmethod
    def from_score(cls, score: float) -> "Grade":
        normalised = max(0.0, min(100.0, round(score, 2)))
        return cls(score=normalised, letter=cls.letter_for(normalised))

    @staticmethod
    def letter_for(score: float) -> str:
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
        return {"score": self.score, "grade": self.letter}
