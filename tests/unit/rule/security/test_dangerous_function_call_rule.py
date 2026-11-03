from gruffpy.rule.security.dangerous_function_call_rule import DangerousFunctionCallRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_eval_emits():
    """Report one finding, with target ``eval``, for ``eval`` on user input."""
    src = "eval(user_input)\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "eval"


def test_exec_emits():
    """Report one finding for an ``exec`` call on a literal."""
    src = "exec('print(1)')\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_compile_emits():
    """Report one finding for a ``compile`` call on literals."""
    src = "compile('x = 1', '<str>', 'exec')\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_static_import_skipped():
    """Report nothing for ``__import__`` of a string literal."""
    src = "__import__('os')\n"
    assert DangerousFunctionCallRule().analyse(make_unit(src), default_ctx()) == []


def test_dynamic_import_emits():
    """Report one finding, with target ``__import__``, for an import of a request-derived name."""
    src = "name = request.args['mod']\n__import__(name)\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "__import__"


def test_method_named_eval_not_flagged():
    """Report nothing for a method that happens to be named ``eval``."""
    src = "obj.eval(x)\n"
    assert DangerousFunctionCallRule().analyse(make_unit(src), default_ctx()) == []
