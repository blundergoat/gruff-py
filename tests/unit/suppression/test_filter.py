from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.suppression.filter import apply_suppressions
from gruffpy.suppression.parser import parse_suppressions


def test_same_line_suppression_hides_only_matching_rule() -> None:
    """Hide only the finding whose rule a same-line ``gruff: disable`` comment names."""
    parsed = parse_suppressions("# gruff: disable=size.file-length\n")
    hidden = _finding("size.file-length", line=1)
    visible = _finding("security.dangerous-function-call", line=1)

    filtered = apply_suppressions([hidden, visible], {"x.py": parsed})

    assert filtered == [visible]


def test_disable_next_targets_only_next_physical_line() -> None:
    """Hide the matching finding on the line after a ``gruff: disable-next`` comment, but not on the line after that."""
    parsed = parse_suppressions("# gruff: disable-next=security.dangerous-function-call\neval('payload')\neval('payload')\n")
    hidden = _finding("security.dangerous-function-call", line=2)
    visible = _finding("security.dangerous-function-call", line=3)

    filtered = apply_suppressions([hidden, visible], {"x.py": parsed})

    assert filtered == [visible]


def test_disable_file_is_file_local() -> None:
    """Apply a ``gruff: disable-file`` comment only to findings in its own file."""
    parsed = parse_suppressions("# gruff: disable-file=size.file-length\n")
    hidden = _finding("size.file-length", file_path="x.py", line=None)
    other_file_visible = _finding("size.file-length", file_path="other.py", line=None)

    filtered = apply_suppressions([hidden, other_file_visible], {"x.py": parsed})

    assert filtered == [other_file_visible]


def test_unsuppressed_payload_and_fingerprint_are_unchanged() -> None:
    """Return an unsuppressed finding with its payload and fingerprint unchanged."""
    parsed = parse_suppressions("# gruff: disable=size.file-length\n")
    visible = _finding("security.dangerous-function-call", line=1, symbol="load_user")
    before_payload = visible.to_dict()
    before_fingerprint = visible.fingerprint()

    filtered = apply_suppressions([visible], {"x.py": parsed})

    assert filtered == [visible]
    assert filtered[0].to_dict() == before_payload
    assert filtered[0].fingerprint() == before_fingerprint


def _finding(
    rule_id: str,
    *,
    file_path: str = "x.py",
    line: int | None,
    symbol: str | None = None,
) -> Finding:
    """Build a warning-level finding for one rule, with fixed tier, confidence and metadata.

    Args:
        rule_id: Rule id; a ``size.`` prefix selects the size pillar, any other the security pillar.
        file_path: Finding path, which selects the parsed suppressions that apply; ``x.py`` by default.
        line: Start and end line, or None for a file-level finding.
        symbol: Symbol name, or None.

    Returns:
        The finding.
    """
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} message",
        file_path=file_path,
        line=line,
        severity=Severity.WARNING,
        pillar=Pillar.SIZE if rule_id.startswith("size.") else Pillar.SECURITY,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        end_line=line,
        symbol=symbol,
        metadata={"value": 1},
    )
