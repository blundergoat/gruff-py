"""Keep the audit details that explain fewer findings in a report.

A suppression row holds the scope, reason and count without access to any matched value.
SARIF can also show a removed finding as suppressed under the shared contract.
Both records sit beside the analysis report to avoid an import cycle with the filters that create them.
"""

from collections.abc import Sequence
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
            JSON-ready native suppression fields. An unavailable symbol is included as None and an absent source is omitted.
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


def suppression_audit_text(suppressions: Sequence[SuppressionSummary]) -> str:
    """Describe how many findings each active suppression removed and why.
    Terminal, Markdown, browser and CI reports use the same wording so reviewers can trace the decisions across formats.

    Args:
        suppressions: Audit rows in report order. An empty collection gives the reporter no suppression message.

    Returns:
        One shared human-readable line, or an empty string if nothing was suppressed.
    """
    total = sum(row.suppressed for row in suppressions)
    # A zero-match exclusion stays in structured output for audit without adding a human-facing notice.
    if not total:
        return ""
    labels = {"built-in": "builtInTestPath", "inline": "inline", "duplicate": "duplicate"}
    details = "; ".join(
        (
            f"{labels[row.source]}[{', '.join(row.paths)}] {row.rule}: {row.suppressed} ({row.reason})"
            if row.source in labels
            else f"sensitiveExclusions[{row.index}] {row.rule}: {row.suppressed} ({row.reason})"
        )
        for row in suppressions
        if row.suppressed > 0
    )
    return f"Suppressed findings: {total} via {details}"
