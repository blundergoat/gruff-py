from gruffpy.rule.security.dangerous_function_call_rule import DangerousFunctionCallRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_eval_emits():
    src = "eval(user_input)\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "eval"


def test_exec_emits():
    src = "exec('print(1)')\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_compile_emits():
    src = "compile('x = 1', '<str>', 'exec')\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_static_import_skipped():
    src = "__import__('os')\n"
    assert DangerousFunctionCallRule().analyse(make_unit(src), default_ctx()) == []


def test_dynamic_import_emits():
    src = "name = request.args['mod']\n__import__(name)\n"
    findings = DangerousFunctionCallRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "__import__"


def test_method_named_eval_not_flagged():
    src = "obj.eval(x)\n"
    assert DangerousFunctionCallRule().analyse(make_unit(src), default_ctx()) == []
