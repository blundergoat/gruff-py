from gruff.rule.docs.stale_param_doc_rule import StaleParamDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_matching_param_emits_nothing():
    src = 'def f(x):\n    """Doc.\n\n    Args:\n        x: a value.\n    """\n    return x\n'
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_stale_param_emits():
    src = (
        "def f(x):\n"
        '    """Doc.\n\n'
        "    Args:\n"
        "        x: a value.\n"
        "        old_param: a leftover.\n"
        '    """\n'
        "    return x\n"
    )
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_param"


def test_no_docstring_skipped():
    src = "def f(x):\n    return x\n"
    assert StaleParamDocRule().analyse(make_unit(src), default_ctx()) == []


def test_renamed_param_emits():
    src = (
        "def f(new_name):\n"
        '    """Doc.\n\n'
        "    Args:\n"
        "        old_name: a value.\n"
        '    """\n'
        "    return new_name\n"
    )
    findings = StaleParamDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "old_name"
