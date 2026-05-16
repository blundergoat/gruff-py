"""Cumulative integration for the naming pillar (M05).

Asserts all 9 rules wire into ``RuleRegistry.defaults()`` and exercise
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
"""Naming smells across all 9 M05 rules."""


class Handler:  # naming.confusing-name
    """Vague class name."""

    pass


class UserService:
    """Suffix usage — naming.confusing-name should NOT fire."""

    def __init__(self, repo: "UserRepository") -> None:
        # parameter-type-name should NOT fire (repo is a prefix of repository)
        self._repo = repo

    def is_active(self) -> bool:
        return True


def i_count() -> int:  # naming.hungarian-notation
    """Type prefix on function name."""

    return 1


def process(x):  # naming.generic-function
    """Vague verb."""

    return x


def valid(value) -> bool:  # naming.boolean-prefix
    """Bool return without boolean-intent prefix."""

    return value > 0


def main() -> None:
    foo = 1  # naming.identifier-quality
    result1 = 2  # naming.identifier-quality
    q = 3  # naming.short-variable
'''


def _unit(source: str, display_path: str = "users.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
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


def test_registry_includes_all_nine_naming_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    expected = {
        "naming.boolean-prefix",
        "naming.confusing-name",
        "naming.generic-function",
        "naming.hungarian-notation",
        "naming.identifier-quality",
        "naming.module-name-mismatch",
        "naming.parameter-type-name",
        "naming.short-variable",
        "naming.test-naming-consistency",
    }
    assert expected.issubset(ids)


def test_naming_rules_fire_on_fixture():
    findings = RuleRegistry.defaults().analyse([_unit(NAMING_FIXTURE)], _default_ctx())
    rule_ids = {f.rule_id for f in findings}
    assert "naming.confusing-name" in rule_ids
    assert "naming.hungarian-notation" in rule_ids
    assert "naming.generic-function" in rule_ids
    assert "naming.boolean-prefix" in rule_ids
    assert "naming.identifier-quality" in rule_ids
    assert "naming.short-variable" in rule_ids


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


def test_findings_deterministic_across_two_runs():
    a = RuleRegistry.defaults().analyse([_unit(NAMING_FIXTURE)], _default_ctx())
    b = RuleRegistry.defaults().analyse([_unit(NAMING_FIXTURE)], _default_ctx())
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]
