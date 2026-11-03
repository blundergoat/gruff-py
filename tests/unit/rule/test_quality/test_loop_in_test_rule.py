import pytest

from gruffpy.rule.rule import Rule
from gruffpy.rule.test_quality.loop_assertion_without_message_rule import LoopAssertionWithoutMessageRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("with self.subTest(value=value):\n                assert double(value) == want", 0),
        ("with self.subTest():\n                assert double(value) == want", 1),
        ("with other.subTest(value=value):\n                assert double(value) == want", 1),
        ("with self.subTest(value=value):\n                assert double(value) == want\n            assert valid(value)", 1),
        ("with self.subTest(value=value):\n                if valid(value):\n                    assert double(value) == want", 1),
    ],
    ids=["named-subtest", "unnamed-subtest", "other-receiver", "uncovered-assertion", "branching-subtest"],
)
@pytest.mark.parametrize("rule", [LoopAssertionWithoutMessageRule()], ids=["assertion-message"])
def test_subtest_loop_keeps_case_context_and_unsafe_controls(body: str, expected: int, rule: Rule) -> None:
    """Accept the report's subTest idiom while retaining assertion-hiding loops.

    Args:
        body: Loop body exercising case context or one unsafe variation.
        expected: Finding count for each loop rule.
        rule: Loop detector whose failure-context contract is checked.

    Returns:
        None.
    """
    source = (
        "import unittest\n"
        "class SubTestLoopTest(unittest.TestCase):\n"
        "    def test_doubles_loop(self):\n"
        "        for value, want in ((1, 2), (2, 4), (3, 6)):\n"
        f"            {body}\n"
    )
    findings = rule.analyse(make_unit(source), default_ctx())
    assert len(findings) == expected
