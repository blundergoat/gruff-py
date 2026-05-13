"""``test-quality.test-function-too-long`` — test function exceeds line threshold.

Consumes the M02 ``lines_for_size`` helper per ADR-002 so the line count
matches the size pillar's policy byte-for-byte.
"""

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import lines_for_size, parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import test_functions


class TestFunctionTooLongRule(Rule):
    ID = "test-quality.test-function-too-long"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Test function too long",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 50, "error": 100},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        warning = settings.numeric_threshold("warning")
        error = settings.numeric_threshold("error")
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            lines = lines_for_size(fn)
            if lines <= warning:
                continue
            severity = Severity.ERROR if lines > error else Severity.WARNING
            threshold = error if severity is Severity.ERROR else warning
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} is {lines} lines, above the "
                        f"{severity.value} threshold of {threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Split the test into focused cases or extract setup into a fixture."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "lines": lines,
                        "threshold": threshold,
                        "thresholdType": severity.value,
                    },
                ),
            )
        return findings
