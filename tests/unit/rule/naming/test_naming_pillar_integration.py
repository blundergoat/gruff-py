"""Cumulative integration for the naming pillar.

Asserts all naming rules wire into ``RuleRegistry.defaults()`` and exercise
expected positives + negatives on a single fixture.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

NAMING_FIXTURE = '''
"""Naming smells across every rule in the naming pillar."""


class Handler:  # naming.confusing-name
    """Vague class name."""

    pass


class UserService:
    """Suffix usage - naming.confusing-name should NOT fire."""

    def __init__(self, repo: "UserRepository") -> None:
        self._repo = repo

    def is_active(self) -> bool:
        return True


def i_count() -> int:  # naming.hungarian-notation
    """Type prefix on function name."""

    return 1


def process(x):  # naming.generic-function
    """Vague verb."""

    return x


def status(value) -> bool:  # naming.boolean-prefix
    """Bool return without boolean-intent prefix."""

    return value > 0


def load_cfg():  # naming.abbreviation
    """Abbreviated function name."""

    return None


def main() -> None:
    foo = 1  # naming.identifier-quality
    result1 = 2  # naming.identifier-quality
    q = 3  # naming.short-variable
'''


def _unit(source: str, display_path: str = "users.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _default_ctx() -> RuleContext:
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        d = rule.definition()
        rules[d.id] = RuleSettings(
            enabled=True,
            thresholds=dict(d.default_thresholds),
            options=dict(d.default_options),
        )
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_includes_all_naming_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    expected = {
        "naming.abbreviation",
        "naming.boolean-prefix",
        "naming.confusing-name",
        "naming.generic-function",
        "naming.hungarian-notation",
        "naming.identifier-quality",
        "naming.module-name-mismatch",
        "naming.short-variable",
        "naming.test-naming-consistency",
    }
    assert expected.issubset(ids)


_EXPECTED_NAMING_RULE_IDS_FIRED = {
    "naming.confusing-name",
    "naming.hungarian-notation",
    "naming.generic-function",
    "naming.boolean-prefix",
    "naming.abbreviation",
    "naming.identifier-quality",
    "naming.short-variable",
}


def test_naming_rules_fire_on_fixture():
    findings = RuleRegistry.defaults().analyse([_unit(NAMING_FIXTURE)], _default_ctx())
    rule_ids = {f.rule_id for f in findings}
    assert _EXPECTED_NAMING_RULE_IDS_FIRED.issubset(rule_ids), (
        f"missing rule ids: {_EXPECTED_NAMING_RULE_IDS_FIRED - rule_ids}"
    )


def test_module_name_mismatch_fires_when_filename_wrong():
    # Single-class module named users.py with class UserService
    findings = RuleRegistry.defaults().analyse(
        [_unit("class UserService:\n    pass\n", display_path="users.py")],
        _default_ctx(),
    )
    mismatch = [f for f in findings if f.rule_id == "naming.module-name-mismatch"]
    assert len(mismatch) == 1


def test_module_name_mismatch_silent_when_filename_matches():
    findings = RuleRegistry.defaults().analyse(
        [_unit("class UserService:\n    pass\n", display_path="user_service.py")],
        _default_ctx(),
    )
    mismatch = [f for f in findings if f.rule_id == "naming.module-name-mismatch"]
    assert mismatch == []
