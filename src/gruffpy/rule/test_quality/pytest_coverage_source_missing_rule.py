"""``test-quality.pytest-coverage-source-missing`` — ``[tool.coverage.run].source`` empty or absent.

Without an explicit source list, coverage measurement is implicit and
misses modules that aren't imported during the suite. The rule wants
``source = ["my_package"]`` declared.
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


class PytestCoverageSourceMissingRule(Rule):
    ID = "test-quality.pytest-coverage-source-missing"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Coverage source missing",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None or not any(True for _ in test_functions(unit)):
            return []
        config = read_pytest_config(context.project_root)
        if not config.is_present or config.has_coverage_source():
            return []
        definition = self.definition()
        return [
            Finding(
                rule_id=definition.id,
                message="Coverage `source` is empty or absent — coverage may be incomplete.",
                file_path=str(Path(context.project_root) / "pyproject.toml"),
                line=None,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                remediation=(
                    'Add `source = ["<package>"]` to `[tool.coverage.run]` so coverage '
                    "measures every module, even those not imported by the suite."
                ),
                secondary_pillars=definition.secondary_pillars,
                metadata={"projectRoot": context.project_root},
            ),
        ]
