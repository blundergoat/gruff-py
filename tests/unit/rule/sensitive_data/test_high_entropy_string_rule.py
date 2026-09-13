from dataclasses import replace

import pytest

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.severity import Severity
from gruffpy.rule.context import RuleContext
from gruffpy.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_HIGH_ENTROPY = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1jD8wEr+/="
# Sixteen symbols cycled cannot pass 4 bits per character, so this 36-character token sits under the 4.2 default.
_CYCLED_TOKEN = ("a1b2c3d4" + "e5f6g7h8") * 2 + "a1b2"


def _context_with_thresholds(thresholds: dict[str, int | float]) -> RuleContext:
    """Return the default context with this rule's thresholds replaced.

    Args:
        thresholds: The ``minLength`` and ``entropy`` values to configure.

    Returns:
        Context whose high-entropy-string settings carry the given thresholds.
    """
    context = default_ctx()
    settings = context.config.rule_settings(HighEntropyStringRule.ID)
    config = context.config.with_rule_settings(HighEntropyStringRule.ID, replace(settings, thresholds=thresholds))
    return replace(context, config=config)


def test_definition_publishes_the_ratified_family_contract() -> None:
    """Hold the contract ratified on 2026-09-02, where py had shipped low confidence at a hardcoded 20 and 4.5."""
    definition = HighEntropyStringRule().definition()

    assert (definition.default_severity, definition.confidence, definition.default_enabled) == (Severity.WARNING, Confidence.MEDIUM, True)
    assert definition.default_thresholds == {"minLength": 32, "entropy": 4.2}


@pytest.mark.parametrize(
    ("token", "lowered"),
    [
        (_HIGH_ENTROPY[:24], {"minLength": 20, "entropy": 4.2}),
        (_CYCLED_TOKEN, {"minLength": 32, "entropy": 3.5}),
    ],
    ids=["min-length", "entropy"],
)
def test_configured_threshold_is_honoured(token: str, lowered: dict[str, int | float]) -> None:
    """Keep a token silent at the default bar and report it once, when configuration lowers that bar.

    Args:
        token: Literal that one default threshold keeps out.
        lowered: Thresholds with that one bar lowered to admit the token.
    """
    unit = make_unit(f"TOKEN = {token!r}\n")

    assert HighEntropyStringRule().analyse(unit, default_ctx()) == []
    assert [finding.rule_id for finding in HighEntropyStringRule().analyse(unit, _context_with_thresholds(lowered))] == [HighEntropyStringRule.ID]


def test_high_entropy_random_string_emits():
    src = f"KEY = {_HIGH_ENTROPY!r}\n"
    findings = HighEntropyStringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata == {"preview": "[redacted]"}


def test_high_entropy_finding_publishes_no_value_derived_statistic():
    """FAMILY-CONTRACT section 5 forbids publishing the matched value's length or entropy."""
    src = f"KEY = {_HIGH_ENTROPY!r}\n"
    findings = HighEntropyStringRule().analyse(make_unit(src), default_ctx())
    assert "entropy" not in findings[0].metadata
    assert "length" not in findings[0].metadata
    assert str(len(_HIGH_ENTROPY)) not in str(findings[0].metadata)


def test_pascal_case_identifier_skipped():
    src = "name = 'SomeReallyLongPascalCaseIdentifier'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_path_string_skipped():
    src = "PATH = '/usr/local/bin/some_random_binary_name'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_short_high_entropy_skipped():
    src = "key = 'aB3xF7p1'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_low_entropy_long_string_skipped():
    src = "x = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_assignment_key_and_value_are_judged_apart() -> None:
    """Keep an environment assignment quiet when neither its key nor its value is secret-shaped.

    Joined, ``AWS_DEFAULT_REGION=ap-southeast-2`` measured 33 characters at 4.62 bits per character.
    """
    src = "AWS_DEFAULT_REGION=" + "ap-southeast-2\nAPI_TOKEN=" + "short-value\n"
    assert HighEntropyStringRule().analyse(make_unit(src, ".env.example"), default_ctx()) == []


def test_padded_base64_secret_still_emits() -> None:
    """Report a padded base64 secret whose padding the candidate boundary now trims."""
    padded = "c2VjcmV0LXZhbHVl" + "LXdpdGgtcGFkZGlu" + "Zy0xMjM0NTY3OA=="
    findings = HighEntropyStringRule().analyse(make_unit(f"SESSION_KEY={padded}\n", ".env"), default_ctx())
    assert len(findings) == 1
