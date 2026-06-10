from dataclasses import replace

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality.extends_production_class_rule import (
    ExtendsProductionClassRule,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_test_class_inheriting_production_emits():
    src = "class TestService(Service):\n    def test_x(self):\n        assert True\n"
    findings = ExtendsProductionClassRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_class_inheriting_order_service_emits():
    src = "class TestOrder(OrderService):\n    def test_x(self):\n        assert True\n"
    findings = ExtendsProductionClassRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_usecase_suffix_still_emits():
    src = "class TestThing(UseCase):\n    def test_x(self):\n        assert True\n"
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


def test_django_and_drf_testcase_suffixes_are_skipped():
    src = "\n".join(
        [
            "class TestOrderApi(APITestCase):",
            "    def test_x(self):",
            "        assert True",
            "",
            "class TestOrderDb(TransactionTestCase):",
            "    def test_x(self):",
            "        assert True",
            "",
            "class TestOrderSimple(SimpleTestCase):",
            "    def test_x(self):",
            "        assert True",
            "",
        ]
    )
    assert ExtendsProductionClassRule().analyse(make_unit(src), default_ctx()) == []


def test_snake_case_test_case_suffix_is_skipped():
    src = "class TestOrder(wc_unit_test_case):\n    def test_x(self):\n        assert True\n"
    assert ExtendsProductionClassRule().analyse(make_unit(src), default_ctx()) == []


def test_additional_test_bases_exact_terminal_match_skips():
    src = "class TestBrowser(WebTest):\n    def test_x(self):\n        assert True\n"
    ctx = _ctx_with_options({"additionalTestBases": ["WebTest"]})

    assert ExtendsProductionClassRule().analyse(make_unit(src), ctx) == []


def test_additional_test_bases_exact_dotted_match_skips():
    src = (
        "class TestBrowser(project.testing.WebTest):\n    def test_x(self):\n        assert True\n"
    )
    ctx = _ctx_with_options({"additionalTestBases": ["project.testing.WebTest"]})

    assert ExtendsProductionClassRule().analyse(make_unit(src), ctx) == []


def test_additional_test_bases_do_not_substring_match():
    src = "class TestThing(UseCase):\n    def test_x(self):\n        assert True\n"
    ctx = _ctx_with_options({"additionalTestBases": ["Case"]})

    findings = ExtendsProductionClassRule().analyse(make_unit(src), ctx)

    assert len(findings) == 1


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


def _ctx_with_options(options: dict[str, object]) -> RuleContext:
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    settings = config.rule_settings(ExtendsProductionClassRule.ID)
    return RuleContext(
        project_root="/tmp/no-such-root",
        config=config.with_rule_settings(
            ExtendsProductionClassRule.ID,
            replace(settings, options=options),
        ),
    )
