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
    """Comprehensions aren't statement-level loops — they're expressions."""
    src = "def test_foo():\n    xs = [i for i in range(3)]\n    assert len(xs) == 3\n"
    assert LoopInTestRule().analyse(make_unit(src), default_ctx()) == []
