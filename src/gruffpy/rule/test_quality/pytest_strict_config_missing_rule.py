"""``test-quality.pytest-strict-config-missing`` - pyproject lacks strict pytest flags.

Fires at most once per analyse run, gated on at least one test-shaped unit
being in scope (no point flagging configuration on a non-test analyse).
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.test_quality._pytest_config import read_pytest_config
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class PytestStrictConfigMissingRule(Rule):
    """Detect pyproject configurations that omit `--strict-config` and `--strict-markers` flags."""

    ID = "test-quality.pytest-strict-config-missing"

    def definition(self) -> RuleDefinition:
        """Describe the pytest-strict-config-missing rule as a medium-confidence advisory.

        Strict flags are a useful default, and some projects deliberately accept unknown markers for plugin compatibility.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Pytest strict-config missing",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report test-bearing units whose pytest configuration has neither --strict-config nor --strict-markers.

        Units without pytest configuration yield no finding. The rule registry keeps the first of the identical findings from qualifying test files.

        Args:
            unit: Parsed source file used to detect test presence. A missing AST yields no findings.
            context: Rule execution context supplying the project root for pyproject.toml settings cached on first lookup.

        Returns:
            One pyproject.toml-anchored finding when strict flags are
            absent (and the unit has tests), otherwise empty.
        """
        if not _has_tests(unit):
            return []
        config = read_pytest_config(context.project_root)
        if not config.is_present or config.has_strict_config():
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=("Pytest config missing strict flags (`--strict-config` or `--strict-markers`)."),
                file_path="pyproject.toml",
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    'Add `addopts = "--strict-config --strict-markers"` to `[tool.pytest.ini_options]` so unknown options and markers fail fast.'
                ),
                secondary_pillars=definition.secondary_pillars,
            ),
        ]


def _has_tests(unit: AnalysisUnit) -> bool:
    """Check whether the unit contains a function in a recognized test-related scope.

    Args:
        unit: Analysis unit whose parsed tree and test scopes are inspected.

    Returns:
        True when a test-related function is found, including conftest helpers; false for an unparsed unit or no matching functions.
    """
    if unit.tree is None:
        return False
    return any(True for _fn, _scope in test_functions(unit))
