from gruffpy.rule.test_quality.test_function_too_long_rule import TestFunctionTooLongRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_short_test_skipped():
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def test_long_test_emits_warning():
    body = "\n".join(f"    x{i} = {i}" for i in range(60))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["lines"] > 50


def test_very_long_test_emits_error():
    body = "\n".join(f"    x{i} = {i}" for i in range(120))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["thresholdType"] == "error"
