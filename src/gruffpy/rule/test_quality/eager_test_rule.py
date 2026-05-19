"""``test-quality.eager-test`` — test asserts against many unrelated values.

Heuristic: a test that contains more than N top-level ``assert`` statements
(default: 5) is probably testing multiple behaviours. Split it.
"""

import ast

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
    is_assertion_call,
    test_functions,
    walk_test_body,
)


class EagerTestRule(Rule):
    ID = "test-quality.eager-test"

    def definition(self) -> RuleDefinition:
        """Describe the eager-test rule with a configurable assertion threshold (default 5).

        Medium confidence because the threshold is a heuristic — a few extra
        asserts on the same outcome are fine; this rule catches tests that
        verify several unrelated behaviours at once.

        Returns:
            Definition under the test-quality pillar with the
            ``maxAssertions`` threshold key.
        """
        return RuleDefinition(
            id=self.ID,
            name="Eager test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"maxAssertions": 5},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag test functions whose assertion count exceeds the ``maxAssertions`` threshold.

        Counts both bare ``assert`` statements and framework assertion calls
        (``self.assertEqual``, ``pytest.raises``, etc.) anywhere inside the
        test body.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``maxAssertions``
                numeric threshold.

        Returns:
            One finding per test whose assertion count exceeds the threshold.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("maxAssertions")
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            count = sum(
                1
                for node in walk_test_body(fn)
                if isinstance(node, ast.Assert)
                or (isinstance(node, ast.Call) and is_assertion_call(node))
            )
            if count <= threshold:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} contains {count} assertions, above the "
                        f"threshold of {threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Split the test into focused cases — one behaviour per test."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"assertions": count, "threshold": threshold},
                ),
            )
        return findings
