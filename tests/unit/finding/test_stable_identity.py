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
    payload = _finding().to_dict()
    keys = list(payload.keys())
    assert "stableIdentity" in payload
    assert keys.index("stableIdentity") == keys.index("fingerprint") + 1


def test_stable_identity_is_16_lowercase_hex_chars() -> None:
    identity = _finding().stable_identity()
    assert len(identity) == 16
    assert all(c in "0123456789abcdef" for c in identity)


def test_stable_identity_is_deterministic() -> None:
    assert _finding().stable_identity() == _finding().stable_identity()


def test_stable_identity_ignores_line_shifts_when_symbol_is_set() -> None:
    base = _finding(line=10, end_line=10, column=4)
    shifted = _finding(line=42, end_line=42, column=4)
    assert base.stable_identity() == shifted.stable_identity()
    assert base.fingerprint() != shifted.fingerprint()


def test_stable_identity_ignores_end_line_and_column_when_symbol_is_set() -> None:
    base = _finding(line=10, end_line=10, column=4)
    wider = _finding(line=10, end_line=40, column=12)
    assert base.stable_identity() == wider.stable_identity()
    assert base.fingerprint() != wider.fingerprint()


def test_stable_identity_distinguishes_by_rule_id() -> None:
    a = _finding(rule_id="naming.identifier-quality")
    b = _finding(rule_id="naming.short-variable")
    assert a.stable_identity() != b.stable_identity()


def test_stable_identity_distinguishes_by_file() -> None:
    a = _finding(file_path="src/a.py")
    b = _finding(file_path="src/b.py")
    assert a.stable_identity() != b.stable_identity()


def test_stable_identity_distinguishes_by_symbol() -> None:
    a = _finding(symbol="module.foo")
    b = _finding(symbol="module.bar")
    assert a.stable_identity() != b.stable_identity()


def test_stable_identity_message_independent_when_symbol_is_set() -> None:
    base = _finding(message="Identifier 'foo' is generic.")
    reworded = _finding(message="Identifier 'foo' needs a more descriptive name.")
    assert base.stable_identity() == reworded.stable_identity()


def test_stable_identity_falls_back_to_message_when_symbol_is_none() -> None:
    base = _finding(symbol=None, message="Hard-coded secret detected at line 12.")
    same = _finding(symbol=None, message="Hard-coded secret detected at line 12.")
    different = _finding(symbol=None, message="Hard-coded secret detected at line 99.")
    assert base.stable_identity() == same.stable_identity()
    assert base.stable_identity() != different.stable_identity()


def test_symbol_present_and_symbol_none_produce_different_identities() -> None:
    """Symbol-present uses [ruleId, file, symbol]; symbol-absent uses [ruleId, file, message]."""
    with_symbol = _finding(symbol="module.foo", message="Hard-coded secret.")
    without_symbol = _finding(symbol=None, message="Hard-coded secret.")
    assert with_symbol.stable_identity() != without_symbol.stable_identity()


def test_stable_identity_helper_matches_method() -> None:
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
    """The module-level helper is independent of any Finding instance state."""
    args = {"rule_id": "r", "file_path": "f", **kwargs}
    assert stable_identity_for(**args) == stable_identity_for(**args)


def test_stable_identity_handles_php_compatible_slash_escaping() -> None:
    """Cross-port byte equivalence: forward slashes encode like fingerprint_for."""
    identity = stable_identity_for(
        rule_id="size.file-length",
        file_path="path/with/slashes.py",
        symbol="x.y",
        message="",
    )
    assert len(identity) == 16
    # determinism + length is the contract; precise digest belongs in a cross-port
    # ground-truth fixture (see test_fingerprint.PHP_GROUND_TRUTH) once gruff-php
    # M05 lands and the two ports can co-generate expected values.
    again = stable_identity_for(
        rule_id="size.file-length",
        file_path="path/with/slashes.py",
        symbol="x.y",
        message="",
    )
    assert identity == again
