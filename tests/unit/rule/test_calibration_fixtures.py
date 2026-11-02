import ast
from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

_FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "calibration"
_EXPECTATIONS = ("positive", "negative")


def _fixture_cases(expectation: str) -> list[object]:
    """Collect one pytest case per calibration fixture under an expectation folder, named by rule and fixture path.

    Args:
        expectation: Expectation folder to read: ``positive`` or ``negative``.

    Returns:
        Cases of rule id and fixture path in sorted order; empty when the calibration folder is missing.
    """
    cases: list[object] = []
    if not _FIXTURE_ROOT.exists():
        return cases
    for rule_dir in sorted(path for path in _FIXTURE_ROOT.iterdir() if path.is_dir()):
        expectation_dir = rule_dir / expectation
        if not expectation_dir.exists():
            continue
        for fixture_path in sorted(expectation_dir.rglob("*.py")):
            fixture_name = fixture_path.relative_to(expectation_dir).as_posix()
            cases.append(
                pytest.param(
                    rule_dir.name,
                    fixture_path,
                    id=f"{rule_dir.name}:{fixture_name}",
                )
            )
    return cases


def _matching_findings(rule_id: str, fixture_path: Path) -> list:
    """Run one registered rule over a calibration fixture and keep only that rule's findings.

    Args:
        rule_id: Rule to run.
        fixture_path: Fixture source file to analyse.

    Returns:
        The rule's findings for the fixture.

    Raises:
        AssertionError: The rule is a project rule, which this harness cannot run.
    """
    registry = RuleRegistry.defaults()
    rule = registry.get(rule_id)
    assert not isinstance(rule, ProjectRuleProtocol), f"{rule_id} is a project rule; extend the calibration harness before adding fixtures."
    findings = rule.analyse(_unit_from_fixture(fixture_path), _context(registry))
    return [finding for finding in findings if finding.rule_id == rule_id]


@pytest.mark.parametrize(("rule_id", "fixture_path"), _fixture_cases("positive"))
def test_positive_fixture_triggers_rule(rule_id: str, fixture_path: Path) -> None:
    """Report at least one finding from the named rule for each positive calibration fixture.

    Args:
        rule_id: Rule the fixture's folder names; the cases cover every positive fixture.
        fixture_path: Fixture expected to trigger that rule.
    """
    matching_findings = _matching_findings(rule_id, fixture_path)
    assert matching_findings, f"{fixture_path} should trigger {rule_id}."


@pytest.mark.parametrize(("rule_id", "fixture_path"), _fixture_cases("negative"))
def test_negative_fixture_does_not_trigger_rule(rule_id: str, fixture_path: Path) -> None:
    """Report no finding from the named rule for each negative calibration fixture.

    Args:
        rule_id: Rule the fixture's folder names; the cases cover every negative fixture.
        fixture_path: Fixture expected to stay clean for that rule.
    """
    matching_findings = _matching_findings(rule_id, fixture_path)
    assert matching_findings == [], f"{fixture_path} should not trigger {rule_id}."


def _unit_from_fixture(fixture_path: Path) -> AnalysisUnit:
    """Parse a fixture file into a Python analysis unit, linking every non-root AST node to its parent.

    Args:
        fixture_path: Fixture source file.

    Returns:
        The unit, whose display path is relative to the fixture's expectation folder.
    """
    source = fixture_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=str(fixture_path),
            display_path=_display_path(fixture_path),
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _display_path(fixture_path: Path) -> str:
    """Give a fixture's path relative to its nearest expectation folder.

    Args:
        fixture_path: Fixture source file.

    Returns:
        That relative path, or the bare file name when no ancestor is an expectation folder.
    """
    for parent in fixture_path.parents:
        if parent.name in _EXPECTATIONS:
            return fixture_path.relative_to(parent).as_posix()
    return fixture_path.name


def _context(registry: RuleRegistry) -> RuleContext:
    """Build a rule context rooted at the calibration fixtures with the registry's default config.

    Args:
        registry: Registry whose defaults form the config.

    Returns:
        The rule context.
    """
    return RuleContext(
        project_root=str(_FIXTURE_ROOT),
        config=AnalysisConfig.from_registry(registry),
    )
