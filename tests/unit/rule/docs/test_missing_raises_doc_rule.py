import ast

from gruffpy.rule.docs._helpers import has_raise_in_body
from gruffpy.rule.docs.missing_raises_doc_rule import MissingRaisesDocRule
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
    assert "needs a Raises section" in findings[0].message
    assert "raises but has no" not in findings[0].message


def test_no_raise_in_body_skipped():
    src = 'def f(x):\n    """Do."""\n    return x\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_function_raise_does_not_trigger_outer():
    src = 'def f(x):\n    """Do."""\n    def inner():\n        raise ValueError\n    return inner\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_skipped():
    src = "def f():\n    raise ValueError\n"
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def _wrap_in_unary_ops(node: ast.expr, depth: int) -> ast.expr:
    """Return ``node`` wrapped in ``depth`` nested ``not`` operators."""
    for _ in range(depth):
        node = ast.UnaryOp(op=ast.Not(), operand=node)
    return node


def test_deep_expression_tree_does_not_overflow_raise_search():
    module = ast.parse("def f():\n    pass\n")
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)

    fn.body = [ast.Expr(value=_wrap_in_unary_ops(ast.Constant(value=0), depth=2000))]

    assert has_raise_in_body(fn) is False
