from gruffpy.rule.test_quality.sut_not_called_rule import SutNotCalledRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_test_with_sut_call_skipped():
    src = "def test_foo():\n    result = my_function(42)\n    assert result == 42\n"
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_test_with_only_mocks_emits():
    src = (
        "from unittest.mock import Mock\n"
        "def test_foo():\n"
        "    mock = Mock()\n"
        "    mock.assert_called()\n"
    )
    findings = SutNotCalledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_with_only_assertions_emits():
    src = "def test_foo():\n    assert True\n"
    findings = SutNotCalledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_with_pytest_raises_and_sut():
    src = (
        "import pytest\n"
        "def test_foo():\n"
        "    with pytest.raises(ValueError):\n"
        "        my_function(-1)\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []
