from gruff.rule.test_quality.empty_parametrize_rule import EmptyParametrizeRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_empty_list_emits():
    src = "import pytest\n@pytest.mark.parametrize('x', [])\ndef test_foo(x):\n    assert True\n"
    findings = EmptyParametrizeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_empty_list_skipped():
    src = (
        "import pytest\n"
        "@pytest.mark.parametrize('x', [1, 2, 3])\n"
        "def test_foo(x):\n"
        "    assert True\n"
    )
    assert EmptyParametrizeRule().analyse(make_unit(src), default_ctx()) == []
