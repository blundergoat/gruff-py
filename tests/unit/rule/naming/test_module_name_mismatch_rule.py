import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.module_name_mismatch_rule import ModuleNameMismatchRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    tree = ast.parse(source)
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = ModuleNameMismatchRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_user_service_in_users_py_fires():
    src = "class UserService:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "users.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "user_service.py"


def test_matching_filename_does_not_fire():
    src = "class UserService:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "user_service.py"), _ctx())
    assert findings == []


def test_package_path_tokens_can_complete_class_name():
    src = "class ConfigLoader:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "src/gruffpy/config/loader.py"), _ctx())
    assert findings == []


def test_multi_segment_package_path_tokens_can_complete_class_name():
    src = "class SingleImplementorProtocolRule:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "src/gruffpy/rule/design/single_implementor_protocol_rule.py"), _ctx()
    )
    assert findings == []


def test_role_suffix_can_be_completed_by_package_path():
    src = "class ProjectRuleProtocol:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "src/gruffpy/rule/project_rule.py"), _ctx()
    )
    assert findings == []


def test_matcher_suffix_can_be_completed_by_package_path():
    src = "class GitignoreMatcher:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "src/gruffpy/source/gitignore.py"), _ctx()
    )
    assert findings == []


def test_conventional_module_name_can_group_domain_exceptions():
    src = "class ConfigError:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "src/gruffpy/config/exceptions.py"), _ctx()
    )
    assert findings == []


def test_http_server_acronym():
    src = "class HTTPServer:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "server.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "http_server.py"


def test_joined_initialism_filename_matches():
    src = "class NPathComplexityRule:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "src/gruffpy/rule/complexity/npath_complexity_rule.py"), _ctx()
    )
    assert findings == []


def test_joined_initialism_suggestion_uses_canonical_filename():
    src = "class NPathComplexityRule:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "complexity_rule.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "npath_complexity_rule.py"


def test_multiple_public_classes_does_not_fire():
    src = "class A:\n    pass\nclass B:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "ab.py"), _ctx())
    assert findings == []


def test_private_class_ignored():
    src = "class _Helper:\n    pass\nclass User:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "users.py"), _ctx())
    # Single PUBLIC class is `User`; expected `user.py`
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "user.py"


def test_init_py_skipped():
    src = "class User:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "__init__.py"), _ctx())
    assert findings == []


def test_no_class_does_not_fire():
    src = "x = 1\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "things.py"), _ctx())
    assert findings == []


def test_router_module_with_envelope_dataclass_does_not_fire():
    # Field-report shape: a routing module with ~10 public functions whose one
    # public class is a frozen-dataclass return envelope. The module IS the
    # router; renaming it after the envelope is semantically wrong.
    handlers = "\n\n".join(
        f"def {name}(request):\n    return RenderedResponse(body={name!r}, status=200)"
        for name in (
            "route_home",
            "route_login",
            "route_logout",
            "route_profile",
            "route_search",
            "route_settings",
            "route_upload",
            "route_download",
            "route_health",
            "route_metrics",
        )
    )
    src = (
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class RenderedResponse:\n"
        "    body: str\n"
        "    status: int\n\n" + handlers + "\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "response.py"), _ctx())
    assert findings == []


def test_prompt_builder_module_with_envelope_dataclass_does_not_fire():
    # Field-report shape: constants + four public functions + a frozen
    # dataclass used as a builder's return shape.
    src = (
        "from dataclasses import dataclass\n\n"
        'SYSTEM_PREAMBLE = "You are foo."\n'
        "MAX_TOKENS = 4096\n\n"
        "@dataclass(frozen=True)\n"
        "class FooPrompt:\n"
        "    system: str\n"
        "    user: str\n\n"
        "def build_system_prompt(context):\n"
        "    return SYSTEM_PREAMBLE\n\n"
        "def build_user_prompt(question):\n"
        "    return question\n\n"
        "def trim_to_budget(text):\n"
        "    return text[:MAX_TOKENS]\n\n"
        "def make_prompt(context, question):\n"
        "    return FooPrompt(system=build_system_prompt(context), "
        "user=build_user_prompt(question))\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "agents/foo.py"), _ctx())
    assert findings == []


def test_private_module_filename_does_not_fire():
    # Field-report shape: underscore-prefixed (private-by-convention) module.
    # Zero public functions here so only the private-filename guard applies -
    # renaming a private module for its result type is pure churn.
    src = (
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class LookupResult:\n"
        "    value: str\n"
        "    found: bool\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "_internal_lookup.py"), _ctx())
    assert findings == []


def test_test_prefixed_module_with_single_testcase_does_not_fire():
    # Field shape: a pytest/unittest module named for discovery, holding one
    # `*Tests` class. Renaming to `challenge_tests.py` would break collection.
    src = (
        "import unittest\n\n"
        "class ChallengeTests(unittest.TestCase):\n"
        "    def test_creates(self):\n"
        "        assert True\n"
    )
    findings = ModuleNameMismatchRule().analyse(
        _unit(src, "service/server/tests/test_challenges.py"), _ctx()
    )
    assert findings == []


def test_test_suffixed_module_does_not_fire():
    src = "class WidgetBehaviour:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "widget_test.py"), _ctx())
    assert findings == []


def test_non_test_module_with_single_class_still_fires():
    # Guard is filename-convention-scoped: a normal module is unaffected.
    src = "class ChallengeTests:\n    pass\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "challenges.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "challenge_tests.py"


def test_substantial_class_in_utils_py_still_fires():
    # True target: the module's only public symbol is one substantial class
    # with a mismatched filename.
    src = (
        "class OrderProcessor:\n"
        "    def load(self, order_id):\n"
        "        return order_id\n\n"
        "    def validate(self, order):\n"
        "        return bool(order)\n\n"
        "    def price(self, order):\n"
        "        return 0\n\n"
        "    def submit(self, order):\n"
        "        return order\n\n"
        "    def audit(self, order):\n"
        "        return order\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "utils.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "order_processor.py"


def test_two_public_functions_beside_plain_class_do_not_fire():
    src = (
        "class UserService:\n"
        "    pass\n\n"
        "def create_user(name):\n"
        "    return name\n\n"
        "def delete_user(name):\n"
        "    return name\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "users.py"), _ctx())
    assert findings == []


def test_one_public_function_beside_plain_class_still_fires():
    # A single helper beside a non-envelope class does not displace the class
    # as the module's identity.
    src = "class UserService:\n    pass\n\ndef helper(value):\n    return value\n"
    findings = ModuleNameMismatchRule().analyse(_unit(src, "users.py"), _ctx())
    assert len(findings) == 1


def test_envelope_class_with_one_public_function_does_not_fire():
    src = (
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class RenderedResponse:\n"
        "    body: str\n\n"
        "def render(template):\n"
        "    return RenderedResponse(body=template)\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "response.py"), _ctx())
    assert findings == []


def test_envelope_class_alone_still_fires():
    # With no public functions the envelope is the module's identity, so the
    # rename guidance stands.
    src = (
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class RenderedResponse:\n"
        "    body: str\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "response.py"), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["expectedFilename"] == "rendered_response.py"


def test_enum_class_with_public_function_does_not_fire():
    src = (
        "import enum\n\n"
        "class Palette(enum.Enum):\n"
        '    RED = "red"\n'
        '    BLUE = "blue"\n\n'
        "def default_palette():\n"
        "    return Palette.RED\n"
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "colours.py"), _ctx())
    assert findings == []


def test_named_tuple_class_with_public_function_does_not_fire():
    src = (
        "from typing import NamedTuple\n\n"
        "class ParseResult(NamedTuple):\n"
        "    value: str\n"
        "    rest: str\n\n"
        "def parse(text):\n"
        '    return ParseResult(value=text, rest="")\n'
    )
    findings = ModuleNameMismatchRule().analyse(_unit(src, "scanner.py"), _ctx())
    assert findings == []
