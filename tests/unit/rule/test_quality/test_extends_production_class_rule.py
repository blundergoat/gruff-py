from gruffpy.rule.test_quality.extends_production_class_rule import (
    ExtendsProductionClassRule,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_test_class_inheriting_production_emits():
    src = "class TestService(Service):\n    def test_x(self):\n        assert True\n"
    findings = ExtendsProductionClassRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_class_inheriting_production_emits_under_tests_directory():
    src = "class TestService(Service):\n    def test_x(self):\n        assert True\n"
    findings = ExtendsProductionClassRule().analyse(
        make_unit(src, "tests/unit/test_service.py"), default_ctx()
    )
    assert len(findings) == 1


def test_test_class_inheriting_testcase_skipped():
    src = "class TestService(TestCase):\n    def test_x(self):\n        assert True\n"
    assert ExtendsProductionClassRule().analyse(make_unit(src), default_ctx()) == []


def test_non_test_class_skipped():
    src = "class MyClass(Service):\n    pass\n"
    assert ExtendsProductionClassRule().analyse(make_unit(src), default_ctx()) == []


def test_production_rule_file_with_test_in_path_skipped():
    src = "class TestFunctionTooLongRule(Rule):\n    pass\n"
    findings = ExtendsProductionClassRule().analyse(
        make_unit(src, "src/gruffpy/rule/test_quality/test_function_too_long_rule.py"),
        default_ctx(),
    )
    assert findings == []
