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
