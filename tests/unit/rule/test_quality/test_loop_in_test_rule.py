import pytest

from gruffpy.rule.rule import Rule
from gruffpy.rule.test_quality.loop_assertion_without_message_rule import LoopAssertionWithoutMessageRule
from gruffpy.rule.test_quality.loop_in_test_rule import LoopInTestRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_for_loop_emits():
    src = "def test_foo():\n    for i in range(3):\n        assert i >= 0\n"
    findings = LoopInTestRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_while_loop_emits():
    src = "def test_foo():\n    while x:\n        assert True\n"
    findings = LoopInTestRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_loop_skipped():
    src = "def test_foo():\n    assert True\n"
    assert LoopInTestRule().analyse(make_unit(src), default_ctx()) == []


def test_list_comprehension_not_flagged():
    """Comprehensions aren't statement-level loops - they're expressions."""
    src = "def test_foo():\n    xs = [i for i in range(3)]\n    assert len(xs) == 3\n"
    assert LoopInTestRule().analyse(make_unit(src), default_ctx()) == []


def test_fixture_loop_with_assertion_context_is_not_flagged():
    src = (
        "FIXTURE_FILES = ['a.json', 'b.json']\n"
        "def test_fixtures_exist(tmp_path):\n"
        "    for name in FIXTURE_FILES:\n"
        "        path = tmp_path / name\n"
        "        assert path.name.endswith('.json'), name\n"
    )
    assert LoopInTestRule().analyse(make_unit(src), default_ctx()) == []


def test_inline_case_loop_with_assertion_context_is_not_flagged():
    src = "def test_cases():\n    for case in [('json', '{}'), ('text', 'ok')]:\n        assert case[1], case\n"
    assert LoopInTestRule().analyse(make_unit(src), default_ctx()) == []


def test_fixture_loop_with_branch_still_fires():
    src = (
        "FIXTURE_FILES = ['a.json', 'b.json']\n"
        "def test_fixtures_exist(tmp_path):\n"
        "    for name in FIXTURE_FILES:\n"
        "        if name.endswith('.json'):\n"
        "            assert True, name\n"
    )
    findings = LoopInTestRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


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
@pytest.mark.parametrize("rule", [LoopInTestRule(), LoopAssertionWithoutMessageRule()], ids=["loop", "assertion-message"])
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
