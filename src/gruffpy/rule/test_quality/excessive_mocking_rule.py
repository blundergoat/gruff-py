"""``test-quality.excessive-mocking`` — test creates too many mocks.

Default threshold: more than 4 mock factory calls in a single test body.
Configurable via the rule's ``max_mocks`` option.
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
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    find_mock_bindings,
    test_functions,
)


class ExcessiveMockingRule(Rule):
    ID = "test-quality.excessive-mocking"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Excessive mocking",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 4},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("warning")
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            mock_count = len(find_mock_bindings(fn))
            if mock_count <= threshold:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} creates {mock_count} mocks, above the threshold "
                        f"of {threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Heavy mocking usually signals coupled design; refactor the SUT "
                        "or write a higher-level test instead."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"mockCount": mock_count, "threshold": threshold},
                ),
            )
        return findings
