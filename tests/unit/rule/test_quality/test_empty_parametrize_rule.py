from gruffpy.rule.test_quality.empty_parametrize_rule import EmptyParametrizeRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_empty_list_emits():
    """Report one finding for a test parametrized with an empty case list.

    Returns:
        None. Checks that the rule emits exactly one finding for an empty case list.
    """
    src = "import pytest\n@pytest.mark.parametrize('x', [])\ndef test_foo(x):\n    assert True\n"
    findings = EmptyParametrizeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_empty_list_skipped():
    """Report nothing for a test parametrized with a non-empty case list.

    Returns:
        None. Checks that the rule returns an empty findings list for the populated case list.
    """
    src = "import pytest\n@pytest.mark.parametrize('x', [1, 2, 3])\ndef test_foo(x):\n    assert True\n"
    assert EmptyParametrizeRule().analyse(make_unit(src), default_ctx()) == []
