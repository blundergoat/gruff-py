"""Define the confidence tiers shown on findings.

Rules choose how certain their signal is and reports show that choice beside severity.
The CLI can use `--min-confidence` to set the lowest tier eligible for the severity gate.
"""

from enum import StrEnum


class Confidence(StrEnum):
    """Represent a finding's low, medium or high confidence tier.

    Reports expose the tier so reviewers can distinguish stronger checks from heuristics.
    Use `meets` to compare it with a caller's minimum confidence.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def meets(self, minimum: "Confidence") -> bool:
        """Check whether a finding reaches the user's minimum confidence.
        The exit gate calls this alongside severity so a lower-confidence finding can stay visible without blocking the run.

        Args:
            minimum: Lowest confidence that may block the run.

        Returns:
            True when this confidence is at or above the floor.
        """
        return _RANK[self] >= _RANK[minimum]


_RANK = {confidence: index for index, confidence in enumerate(Confidence)}
