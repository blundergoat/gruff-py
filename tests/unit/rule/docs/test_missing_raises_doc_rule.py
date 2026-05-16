import ast

from gruff.rule.docs._helpers import raises_in_body
from gruff.rule.docs.missing_raises_doc_rule import MissingRaisesDocRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_documented_raises_emits_nothing():
    src = (
        "def f(x):\n"
        '    """Do.\n\n'
        "    Raises:\n"
        "        ValueError: when x is negative.\n"
        '    """\n'
        "    if x < 0:\n"
        "        raise ValueError\n"
    )
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_raises_without_section_emits():
    src = 'def f(x):\n    """Do."""\n    if x < 0:\n        raise ValueError\n    return x\n'
    findings = MissingRaisesDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_no_raise_in_body_skipped():
    src = 'def f(x):\n    """Do."""\n    return x\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_function_raise_does_not_trigger_outer():
    src = 'def f(x):\n    """Do."""\n    def inner():\n        raise ValueError\n    return inner\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_skipped():
    src = "def f():\n    raise ValueError\n"
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_deep_expression_tree_does_not_overflow_raise_search():
    module = ast.parse("def f():\n    pass\n")
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)

    node: ast.expr = ast.Constant(value=0)
    for _ in range(2000):
        node = ast.UnaryOp(op=ast.Not(), operand=node)
    fn.body = [ast.Expr(value=node)]

    assert raises_in_body(fn) is False
