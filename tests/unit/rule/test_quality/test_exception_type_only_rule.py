"""Captured exception details can be verified after leaving raises."""

import pytest

from gruffpy.rule.test_quality.exception_type_only_rule import ExceptionTypeOnlyRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


@pytest.mark.parametrize(
    ("check", "expected"),
    [
        ("assert str(excinfo.value).splitlines() == ['expected diagnostic']", 0),
        ("assert excinfo.value.code == expected_code", 0),
        ("assert unrelated_value == expected_value", 1),
        ("assert isinstance(excinfo.value, Exception)", 1),
        ("excinfo = another_error\n    assert str(excinfo.value) == 'expected diagnostic'", 1),
    ],
    ids=["message-lines", "error-code", "unrelated-assertion", "type-only", "rebound-capture"],
)
def test_later_checks_bind_to_the_captured_exception(check: str, expected: int) -> None:
    """Retain type-only findings unless the same exception's details are asserted.

    Args:
        check: Statement following the exception context.
        expected: Number of type-only findings.

    Returns:
        None.
    """
    source = f"import pytest\ndef test_diagnostic():\n    with pytest.raises(Exception) as excinfo:\n        run_command()\n    {check}\n"
    assert len(ExceptionTypeOnlyRule().analyse(make_unit(source), default_ctx())) == expected
