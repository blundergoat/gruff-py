"""Cover the additive ``stableIdentity`` field on findings (ADR-020).

The shape is line-insensitive: two findings of the same rule on the same symbol at
different lines share a ``stableIdentity`` but have different ``fingerprint``
values. When ``symbol`` is ``None`` the identity falls back to ``message``, so
message-only rules still get a usable identity at the cost of being
message-dependent.
"""

import pytest

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.fingerprint import stable_identity_for
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


def _finding(
    *,
    rule_id: str = "naming.identifier-quality",
    message: str = "Identifier 'foo' is generic.",
    file_path: str = "src/example.py",
    line: int | None = 10,
    end_line: int | None = 10,
    column: int | None = 4,
    symbol: str | None = "module.foo",
) -> Finding:
    """Build an advisory naming finding whose identity fields can each be overridden.

    Args:
        rule_id: Rule id; the identifier-quality rule by default.
        message: Text used by the stable identity when symbol is None.
        file_path: Display path included in both the fingerprint and stable identity.
        line: Start line included in the fingerprint; None is encoded as null.
        end_line: End line included in the fingerprint; None is encoded as null.
        column: Column included in the fingerprint; None is encoded as null.
        symbol: Symbol name, or None to make the identity use the message.

    Returns:
        Advisory naming finding for fingerprint and stable-identity comparisons.
    """
    return Finding(
        rule_id=rule_id,
        message=message,
        file_path=file_path,
        line=line,
        severity=Severity.ADVISORY,
        pillar=Pillar.NAMING,
        tier=RuleTier.V01,
        confidence=Confidence.MEDIUM,
        end_line=end_line,
        column=column,
        symbol=symbol,
    )


def test_stable_identity_appears_in_to_dict_adjacent_to_fingerprint() -> None:
    """Serialise stableIdentity immediately after fingerprint in a finding's dictionary.

    Returns:
        None. Checks that the finding dictionary contains stableIdentity in the next position after fingerprint.
    """
    payload = _finding().to_dict()
    keys = list(payload.keys())
    assert "stableIdentity" in payload
    assert keys.index("stableIdentity") == keys.index("fingerprint") + 1


def test_stable_identity_is_16_lowercase_hex_chars() -> None:
    """Produce a stable identity of exactly 16 lowercase hexadecimal characters.

    Returns:
        None. Checks the stable identity length and lowercase hexadecimal alphabet.
    """
    identity = _finding().stable_identity()
    assert len(identity) == 16
    assert all(c in "0123456789abcdef" for c in identity)


def test_stable_identity_is_deterministic() -> None:
    """Produce the same stable identity for two identical findings.

    Returns:
        None. Compares the stable identities of two findings built with identical inputs.
    """
    first = _finding().stable_identity()
    second = _finding().stable_identity()
    assert first == second


def test_additive_metadata_does_not_change_fingerprint_or_stable_identity() -> None:
    """Adding explanation metadata leaves the fingerprint and stable identity unchanged.

    Returns:
        None. Checks that adding explanation metadata preserves both identities of the test finding.
    """
    finding = _finding(symbol=None)
    fingerprint_before_metadata = finding.fingerprint()
    identity_before_metadata = finding.stable_identity()

    finding.metadata.update(
        {
            "slot": "label",
            "expressionKind": "call",
            "sanitizerResolution": "wrong-slot",
            "annotationShape": "optional-bool",
        }
    )

    assert finding.fingerprint() == fingerprint_before_metadata
    assert finding.stable_identity() == identity_before_metadata


def test_stable_identity_ignores_line_shifts_when_symbol_is_set() -> None:
    """Keep the stable identity when a finding with a symbol moves to another line, while its fingerprint changes.

    Returns:
        None. Checks for equal stable identities and different fingerprints when a finding with a symbol moves to another line.
    """
    base = _finding(line=10, end_line=10, column=4)
    shifted = _finding(line=42, end_line=42, column=4)
    assert base.stable_identity() == shifted.stable_identity()
    assert base.fingerprint() != shifted.fingerprint()


def test_stable_identity_ignores_end_line_and_column_when_symbol_is_set() -> None:
    """Keep the stable identity when a finding with a symbol changes end line and column, while its fingerprint changes.

    Returns:
        None. Checks for equal stable identities and different fingerprints after changing the end line and column of a finding with a symbol.
    """
    base = _finding(line=10, end_line=10, column=4)
    wider = _finding(line=10, end_line=40, column=12)
    assert base.stable_identity() == wider.stable_identity()
    assert base.fingerprint() != wider.fingerprint()


@pytest.mark.parametrize(
    ("kwargs_a", "kwargs_b"),
    [
        ({"rule_id": "naming.identifier-quality"}, {"rule_id": "naming.short-variable"}),
        ({"file_path": "src/a.py"}, {"file_path": "src/b.py"}),
        ({"symbol": "module.foo"}, {"symbol": "module.bar"}),
    ],
    ids=["rule_id", "file_path", "symbol"],
)
def test_stable_identity_distinguishes_by_identifying_field(kwargs_a: dict, kwargs_b: dict) -> None:
    """The identity must differ when any of [ruleId, file, symbol] differs.

    Args:
        kwargs_a: Override kwargs for the left finding.
        kwargs_b: Override kwargs for the right finding.

    Returns:
        None. Checks that changing the rule, path, or symbol yields a different stable identity in each case.
    """
    assert _finding(**kwargs_a).stable_identity() != _finding(**kwargs_b).stable_identity()


def test_stable_identity_message_independent_when_symbol_is_set() -> None:
    """Keep the stable identity when a finding with a symbol has its message reworded.

    Returns:
        None. Checks that rewording the message preserves the stable identity of a finding with a symbol.
    """
    base = _finding(message="Identifier 'foo' is generic.")
    reworded = _finding(message="Identifier 'foo' needs a more descriptive name.")
    assert base.stable_identity() == reworded.stable_identity()


def test_stable_identity_falls_back_to_message_when_symbol_is_none() -> None:
    """Check the message fallback for otherwise identical findings without a symbol.

    Returns:
        None. Checks for equal identities with matching fixture messages and different identities when the message changes.
    """
    base = _finding(symbol=None, message="Hard-coded secret detected at line 12.")
    same = _finding(symbol=None, message="Hard-coded secret detected at line 12.")
    different = _finding(symbol=None, message="Hard-coded secret detected at line 99.")
    assert base.stable_identity() == same.stable_identity()
    assert base.stable_identity() != different.stable_identity()


def test_symbol_present_and_symbol_none_produce_different_identities() -> None:
    """Check that supplying a symbol changes the stable identity of the sample finding.

    The identity uses [ruleId, file, symbol] when a symbol is supplied and [ruleId, file, message] when it is absent.

    Returns:
        None. Compares the identities of two findings with the same message and different symbol presence.
    """
    with_symbol = _finding(symbol="module.foo", message="Hard-coded secret.")
    without_symbol = _finding(symbol=None, message="Hard-coded secret.")
    assert with_symbol.stable_identity() != without_symbol.stable_identity()


def test_stable_identity_helper_matches_method() -> None:
    """Compute the same stable identity through ``stable_identity_for`` as through the finding's own method.

    Returns:
        None. Checks that the helper and the finding method agree on the identity for the same fields.
    """
    finding = _finding()
    assert finding.stable_identity() == stable_identity_for(
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        symbol=finding.symbol,
        message=finding.message,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"symbol": "module.foo", "message": "ignored when symbol is set"},
        {"symbol": None, "message": "fallback identity uses this string"},
    ],
    ids=["symbol-present", "symbol-absent"],
)
def test_stable_identity_helper_is_pure_function(kwargs: dict) -> None:
    """Repeated calls produce the same stable identity in the symbol-present and symbol-absent cases.

    Args:
        kwargs: Symbol and message inputs; a None symbol exercises the message fallback.

    Returns:
        None. Compares two calls with identical inputs for each symbol case.
    """
    args = {"rule_id": "r", "file_path": "f", **kwargs}
    first = stable_identity_for(**args)
    second = stable_identity_for(**args)
    assert first == second


def test_stable_identity_handles_php_compatible_slash_escaping() -> None:
    """Check that a path containing forward slashes gives a repeatable 16-character stable identity.

    Returns:
        None. Checks the identity length and compares two results for identical inputs.
    """
    identity = stable_identity_for(
        rule_id="size.file-length",
        file_path="path/with/slashes.py",
        symbol="x.y",
        message="",
    )
    assert len(identity) == 16
    # Checking byte equivalence requires a shared expected digest from a gruff-php build that emits stable identities.
    again = stable_identity_for(
        rule_id="size.file-length",
        file_path="path/with/slashes.py",
        symbol="x.y",
        message="",
    )
    assert identity == again
