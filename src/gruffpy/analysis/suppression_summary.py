"""The audit row every suppression class publishes in a report, and the findings section 13c removes.

Lives beside the other report value objects rather than in ``gruffpy.suppression`` because
``gruffpy.analysis.report`` and the suppression channel that fills these rows would otherwise
import each other. An audit row reads no finding, so no matched value material can reach the
report (FAMILY-CONTRACT section 5, search: ``**Forbidden material.**``); a ``SuppressedFinding``
reaches only SARIF, as a result marked suppressed.
"""

from dataclasses import dataclass
from typing import Any

from gruffpy.finding.finding import Finding


@dataclass(frozen=True, slots=True)
class SuppressionSummary:
    """One audit row: the configured or built-in scope, or section 13c class, and how many findings it removed.

    Immutable. Serialised into the report's ``suppressions`` array, matching the family shape
    gruff-rs already ships (``gruff-rs/src/report.rs``, search: ``struct SuppressionSummary``).

    Attributes:
        index: Position in the user's ``sensitiveExclusions`` list; built-in rows number separately,
            and section 13c rows continue the built-in sequence.
        rule: The rule id the row's findings carry; a sensitive-data rule on a configured row.
        paths: The entry's single project-relative path, in the family's list-shaped field.
        symbol: Optional qualified symbol that narrowed the scope, else ``None``.
        reason: The user's rationale from configuration, or the contract's fixed reason on a built-in or section 13c row.
        suppressed: Findings this entry removed; ``0`` is a valid, non-failing result.
        source: ``"built-in"`` on a row the test-path skip produced, ``"inline"`` or
            ``"duplicate"`` on a section 13c row, else ``None`` on a configured entry's row.
    """

    index: int
    rule: str
    paths: tuple[str, ...]
    symbol: str | None
    reason: str
    suppressed: int
    source: str | None = None

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
            **({} if self.source is None else {"source": self.source}),
        }


@dataclass(frozen=True, slots=True)
class SuppressedFinding:
    """A finding another tool's comment or a repeated claim removed (FAMILY-CONTRACT.md section 13c).

    It leaves the findings list, the score and the exit code, and SARIF keeps it as a result marked
    suppressed, so a code-scanning tool shows it as suppressed rather than fixed.

    Attributes:
        finding: The removed finding as its rule reported it.
        justification: The audit reason a SARIF reader sees on the suppressed result.
    """

    finding: Finding
    justification: str
