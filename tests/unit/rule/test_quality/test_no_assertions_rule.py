from gruff.rule.test_quality.no_assertions_rule import NoAssertionsRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_no_assert_emits():
    src = "def test_foo():\n    x = 1\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_skipped():
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_unittest_assert_method_skipped():
    src = "class TestX:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_pytest_raises_block_skipped():
    src = (
        "import pytest\n"
        "def test_foo():\n"
        "    with pytest.raises(ValueError):\n"
        "        raise ValueError\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_non_test_function_skipped():
    src = "def helper():\n    x = 1\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []
