import ast

from gruffpy.rule.docs._helpers import has_raise_in_body
from gruffpy.rule.docs.missing_raises_doc_rule import MissingRaisesDocRule
from tests.unit.rule.docs._helpers import default_ctx, every_callable_ctx, make_unit


def test_documented_raises_emits_nothing():
    """Report nothing when a ``Raises`` section documents the raise."""
    src = 'def f(x):\n    """Do.\n\n    Raises:\n        ValueError: when x is negative.\n    """\n    if x < 0:\n        raise ValueError\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_raises_without_section_emits():
    """Report a raising function without a ``Raises`` section once, with a message asking for one."""
    src = 'def f(x):\n    """Do."""\n    if x < 0:\n        raise ValueError\n    return x\n'
    findings = MissingRaisesDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert "needs a Raises section" in findings[0].message
    assert "raises but has no" not in findings[0].message


def test_no_raise_in_body_skipped():
    """Report nothing for a function that never raises."""
    src = 'def f(x):\n    """Do."""\n    return x\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_nested_function_raise_does_not_trigger_outer():
    """Report nothing for an outer function whose only raise is in a nested function."""
    src = 'def f(x):\n    """Do."""\n    def inner():\n        raise ValueError\n    return inner\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_skipped():
    """Report nothing for a raising function without a docstring."""
    src = "def f():\n    raise ValueError\n"
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_reported_only_with_every_callable():
    """Report a raising private function only when ``everyCallable`` is set."""
    src = 'def _f(x):\n    """Do."""\n    if x < 0:\n        raise ValueError\n    return x\n'
    assert MissingRaisesDocRule().analyse(make_unit(src), default_ctx()) == []
    findings = MissingRaisesDocRule().analyse(make_unit(src), every_callable_ctx(MissingRaisesDocRule.ID))
    assert [f.symbol for f in findings] == ["_f"]


def _wrap_in_unary_ops(node: ast.expr, depth: int) -> ast.expr:
    """Return ``node`` wrapped in ``depth`` nested ``not`` operators.

    Args:
        node: Expression to wrap.
        depth: Number of ``not`` operators to apply.

    Returns:
        The outermost ``not`` expression, or node itself when depth is 0.
    """
    for _ in range(depth):
        node = ast.UnaryOp(op=ast.Not(), operand=node)
    return node


def test_deep_expression_tree_does_not_overflow_raise_search():
    """Search a body of 2,000 nested ``not`` operators without error and find no raise."""
    module = ast.parse("def f():\n    pass\n")
    fn = module.body[0]
    assert isinstance(fn, ast.FunctionDef)

    fn.body = [ast.Expr(value=_wrap_in_unary_ops(ast.Constant(value=0), depth=2000))]

    assert has_raise_in_body(fn) is False
