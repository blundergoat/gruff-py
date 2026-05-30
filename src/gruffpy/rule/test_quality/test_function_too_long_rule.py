"""``test-quality.test-function-too-long`` - test function exceeds line threshold.

Consumes the ``lines_for_size`` helper per ADR-002 so the line count
matches the size pillar's policy byte-for-byte.
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
from gruffpy.rule.size._lines import lines_for_size, parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class TestFunctionTooLongRule(Rule):
    """Flag test functions whose `lines_for_size` count exceeds the configured threshold."""

    ID = "test-quality.test-function-too-long"

    def definition(self) -> RuleDefinition:
        """Describe the test-function-too-long rule with a single 100-line default threshold.

        High confidence because line count is a deterministic structural
        metric; long tests reliably hide multiple behaviours and resist
        future maintenance. One value plus one severity per rubric (ADR-014).

        Returns:
            Definition with a single ``threshold`` of 100 at error severity.
        """
        return RuleDefinition(
            id=self.ID,
            name="Test function too long",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=100,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag test functions whose ``lines_for_size`` count exceeds the configured threshold.

        Uses the size-pillar's shared ``lines_for_size`` helper per ADR-002
        so the line metric stays consistent with other size rules. With the
        default same-value threshold a finding emits as the default severity
        (warning); projects that split the ``warning``/``error`` keys can
        get severity escalation past the higher tier.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``warning``/
                ``error`` line-count thresholds.

        Returns:
            One finding per test whose size exceeds either threshold.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            lines = lines_for_size(fn)
            threshold_match = settings.high_value_threshold_match(lines)
            if threshold_match is None:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} is {lines} lines, above the "
                        f"{threshold_match.severity.value} threshold of "
                        f"{threshold_match.threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=threshold_match.severity,
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
                        "measuredValue": lines,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )
        return findings
