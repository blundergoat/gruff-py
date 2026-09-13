"""The audit row every configured sensitive-data exclusion publishes in a report.

Lives beside the other report value objects rather than in ``gruffpy.suppression`` because
``gruffpy.analysis.report`` and the suppression channel that fills these rows would otherwise
import each other. Nothing here reads a finding, so no matched value material can reach the
report (FAMILY-CONTRACT section 5, search: ``**Forbidden material.**``).
"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SuppressionSummary:
    """One audit row: the configured scope and how many findings it removed.

    Immutable. Serialised into the report's ``suppressions`` array, matching the family shape
    gruff-rs already ships (``gruff-rs/src/report.rs``, search: ``struct SuppressionSummary``).

    Attributes:
        index: Zero-based position of the entry in the user's ``sensitiveExclusions`` list.
        rule: The sensitive-data rule id the entry silences.
        paths: The entry's single project-relative path, in the family's list-shaped field.
        symbol: Optional qualified symbol that narrowed the scope, else ``None``.
        reason: The user's rationale, reproduced from configuration.
        suppressed: Findings this entry removed; ``0`` is a valid, non-failing result.
    """

    index: int
    rule: str
    paths: tuple[str, ...]
    symbol: str | None
    reason: str
    suppressed: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the native suppression audit row.

        The v3 machine adapter normalizes paths and omits an unavailable
        symbol.

        Returns:
            JSON-ready native suppression fields.
        """
        return {
            "index": self.index,
            "rule": self.rule,
            "paths": list(self.paths),
            "symbol": self.symbol,
            "reason": self.reason,
            "suppressed": self.suppressed,
        }
