from gruffpy.rule.docs.missing_return_doc_rule import MissingReturnDocRule
from tests.unit.rule.docs._helpers import default_ctx, every_callable_ctx, make_unit


def test_documented_returns_emits_nothing():
    src = 'def f() -> int:\n    """Get a thing.\n\n    Returns:\n        int: the thing.\n    """\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_non_none_return_without_section_emits():
    src = 'def f() -> int:\n    """Get a thing."""\n    return 1\n'
    findings = MissingReturnDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "f"
    assert "needs a Returns section" in findings[0].message
    assert "but no Returns section" not in findings[0].message


def test_none_return_skipped():
    src = 'def f() -> None:\n    """Side effect."""\n    print(1)\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_no_annotation_skipped():
    src = 'def f():\n    """Get a thing."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_skipped():
    src = 'def _f() -> int:\n    """X."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_reported_with_every_callable():
    src = 'def _f() -> int:\n    """X."""\n    return 1\n'
    findings = MissingReturnDocRule().analyse(make_unit(src), every_callable_ctx(MissingReturnDocRule.ID))
    assert [f.symbol for f in findings] == ["_f"]


def test_unannotated_value_return_reported_only_with_every_callable():
    src = (
        'def plain(x):\n    """Double."""\n    return x * 2\n\n'
        'async def fetch(x):\n    """Fetch."""\n    return x\n\n'
        'def silent(x):\n    """Log."""\n    print(x)\n    return None\n\n'
        'def gen(x):\n    """Count.\n\n    Yields:\n        int: each value.\n    """\n    yield x\n'
    )
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []
    findings = MissingReturnDocRule().analyse(make_unit(src), every_callable_ctx(MissingReturnDocRule.ID))
    assert sorted(f.symbol for f in findings) == ["fetch", "plain"]
