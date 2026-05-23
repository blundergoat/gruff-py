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

        Medium confidence because some projects intentionally let
        deprecations stay warnings (third-party noise they can't fix); the
        rule recommends the strict default but defers to per-project
        suppression.

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
        """Emit a pyproject-anchored finding when pytest does not escalate ``DeprecationWarning``.

        Only fires when the unit contains at least one test function and a
        pytest config block is present; checks ``filterwarnings`` for an
        ``error::DeprecationWarning`` entry.

        Args:
            unit: Parsed source file used to detect test presence.
            context: Rule execution context supplying the ``project_root``
                used to locate pyproject.toml.

        Returns:
            One pyproject.toml-anchored finding when deprecation warnings
            are not escalated, otherwise empty.
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
                    'Add `filterwarnings = ["error::DeprecationWarning"]` to '
                    "`[tool.pytest.ini_options]` so deprecated APIs fail the suite."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"projectRoot": context.project_root},
            ),
        ]
