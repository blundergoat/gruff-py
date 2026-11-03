"""Cover the sensitive-exclusion matcher paths no end-to-end scan can reach.

``tests/integration/test_sensitive_exclusions.py`` proves the scan-level contract. No sensitive-data
rule stamps a symbol today, so the symbol-equality branch and its narrowing behaviour are only
reachable here, and they are the clause a future symbol-stamping rule will depend on.
"""

from gruffpy.config.sensitive_exclusions import SensitiveExclusion
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.suppression.sensitive_exclusion_filter import partition_sensitive_exclusions

_AWS_RULE = "sensitive-data.aws-access-key"


def _finding(*, file_path: str = "secrets/aws.env", symbol: str | None = None) -> Finding:
    """Build an error-level AWS key finding on line 1, optionally attached to a symbol.

    Args:
        file_path: Finding path; the excluded ``secrets/aws.env`` by default.
        symbol: Symbol that holds the key, or None.

    Returns:
        The finding.
    """
    return Finding(
        rule_id=_AWS_RULE,
        message="AWS access key ID literal in source.",
        file_path=file_path,
        line=1,
        severity=Severity.ERROR,
        pillar=Pillar.SENSITIVE_DATA,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol=symbol,
    )


def _exclusion(*, symbol: str | None = None) -> SensitiveExclusion:
    """Build the single sensitive exclusion entry for the AWS rule on ``secrets/aws.env``.

    Args:
        symbol: Symbol the entry narrows to, or None to cover the whole path.

    Returns:
        The entry at index 0, with its fixed reason.
    """
    return SensitiveExclusion(
        index=0,
        rule=_AWS_RULE,
        path="secrets/aws.env",
        symbol=symbol,
        reason="Synthetic AWS key used by the redaction corpus.",
    )


def test_entry_symbol_suppresses_only_the_finding_carrying_that_symbol() -> None:
    """Suppress only the finding whose symbol the exclusion entry names, keeping a sibling with another symbol and counting one."""
    matching = _finding(symbol="Fixtures.aws_sample")
    other_symbol = _finding(symbol="Fixtures.other_sample")

    kept, summaries = partition_sensitive_exclusions(
        [matching, other_symbol],
        [_exclusion(symbol="Fixtures.aws_sample")],
    )

    assert kept == [other_symbol]
    assert summaries[0].suppressed == 1


def test_entry_without_a_symbol_suppresses_regardless_of_the_finding_symbol() -> None:
    """Suppress every matching finding, with or without a symbol, when the exclusion entry names no symbol."""
    kept, summaries = partition_sensitive_exclusions(
        [_finding(symbol="Fixtures.aws_sample"), _finding()],
        [_exclusion()],
    )

    assert kept == []
    assert summaries[0].suppressed == 2


def test_an_entry_matching_nothing_still_publishes_its_audit_row() -> None:
    """Publish an audit row with a zero suppressed count for an exclusion entry that matches no finding."""
    kept, summaries = partition_sensitive_exclusions([], [_exclusion()])

    assert kept == []
    assert summaries[0].to_dict() == {
        "index": 0,
        "rule": _AWS_RULE,
        "paths": ["secrets/aws.env"],
        "symbol": None,
        "reason": "Synthetic AWS key used by the redaction corpus.",
        "suppressed": 0,
    }
