from gruff.rule.docs.missing_return_doc_rule import MissingReturnDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_documented_returns_emits_nothing():
    src = (
        "def f() -> int:\n"
        '    """Get a thing.\n\n'
        "    Returns:\n"
        "        int: the thing.\n"
        '    """\n'
        "    return 1\n"
    )
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_non_none_return_without_section_emits():
    src = 'def f() -> int:\n    """Get a thing."""\n    return 1\n'
    findings = MissingReturnDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "f"


def test_none_return_skipped():
    src = 'def f() -> None:\n    """Side effect."""\n    print(1)\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_no_annotation_skipped():
    src = 'def f():\n    """Get a thing."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_skipped():
    src = 'def _f() -> int:\n    """X."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []
