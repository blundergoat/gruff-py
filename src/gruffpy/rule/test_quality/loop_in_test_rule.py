"""``test-quality.loop-in-test`` - ``for`` / ``while`` in a test body.

Loops in tests hide assertion-per-iteration semantics and obscure failure
attribution. Prefer ``@pytest.mark.parametrize`` for case enumeration.
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
    test_functions,
    walk_test_body,
)


class LoopInTestRule(Rule):
    """Detect `for` or `while` loops inside test function bodies (prefer `parametrize`)."""

    ID = "test-quality.loop-in-test"

    def definition(self) -> RuleDefinition:
        """Describe the loop-in-test rule as a medium-confidence advisory.

        Medium confidence: most loops in tests do hide per-iteration assertions
        that should be parametrised, but some legitimate cases exist (setting
        up fixture data) - hence advisory rather than warning.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Loop in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag test functions whose body contains a ``for``, ``async for``, or ``while`` loop.

        Stops at the first loop per test (one finding per function is enough);
        catches ``if``/``match`` branching via the separate
        ``conditional-logic`` rule.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per test function containing a loop, anchored at the
            loop node.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.For | ast.AsyncFor | ast.While):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} contains a loop - prefer "
                            f"`@pytest.mark.parametrize` for case enumeration."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Convert the loop into a parametrised test so each case "
                            "produces its own pass/fail signal."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
                break
        return findings
