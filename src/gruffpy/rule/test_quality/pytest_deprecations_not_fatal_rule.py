"""``test-quality.pytest-deprecations-not-fatal`` — DeprecationWarning not escalated to error.

Letting deprecations stay warnings means a deprecated API gets re-introduced
silently and breaks on the eventual removal. The rule wants
``filterwarnings = ["error::DeprecationWarning"]`` or equivalent.
"""

from pathlib import Path

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
    ID = "test-quality.pytest-deprecations-not-fatal"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Pytest deprecations not fatal",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
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
                file_path=str(Path(context.project_root) / "pyproject.toml"),
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
