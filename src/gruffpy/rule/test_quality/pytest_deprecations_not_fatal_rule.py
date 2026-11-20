"""``test-quality.pytest-deprecations-not-fatal`` - DeprecationWarning not escalated to error.

Letting deprecations stay warnings means a deprecated API gets re-introduced
silently and breaks on the eventual removal. The rule wants
``filterwarnings = ["error::DeprecationWarning"]`` or equivalent.
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


class PytestDeprecationsNotFatalRule(Rule):
    """Detect projects whose pytest config does not escalate `DeprecationWarning` to error."""

    ID = "test-quality.pytest-deprecations-not-fatal"

    def definition(self) -> RuleDefinition:
        """Describe the pytest-deprecations-not-fatal rule as a medium-confidence advisory.

        The advisory flags a configuration choice that may be intentional when third-party deprecations must remain warnings.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Pytest deprecations not fatal",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit a pyproject-anchored finding when pytest settings lack a recognized deprecation error filter.

        A bare error filter qualifies, as does an entry that starts with error and contains DeprecationWarning.

        Args:
            unit: Parsed source file used to detect test presence. A missing AST yields no findings.
            context: Rule execution context supplying the project root for pyproject.toml settings cached on first lookup.

        Returns:
            One pyproject.toml-anchored finding for a unit with tests and pytest settings that lack a qualifying filter. Otherwise, an empty list.
        """
        if unit.tree is None or not any(True for _ in test_functions(unit)):
            return []
        config = read_pytest_config(context.project_root)
        if not config.is_present or config.has_deprecations_as_errors():
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message=("Pytest config doesn't escalate DeprecationWarning to error."),
                file_path="pyproject.toml",
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    'Add `filterwarnings = ["error::DeprecationWarning"]` to `[tool.pytest.ini_options]` so deprecated APIs fail the suite.'
                ),
                secondary_pillars=definition.secondary_pillars,
            ),
        ]
