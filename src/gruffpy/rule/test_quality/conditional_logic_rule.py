"""``test-quality.conditional-logic`` — ``if`` / ``elif`` / ``match`` in a test body.

Tests should be deterministic. Conditional logic inside a test body usually
means the test is doing two things in one place — split it.
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


class ConditionalLogicRule(Rule):
    ID = "test-quality.conditional-logic"

    def definition(self) -> RuleDefinition:
        """Describe the conditional-logic-in-test rule as a medium-confidence advisory.

        Medium confidence because a stray ``if`` in a test body usually
        indicates branching behaviour better expressed as parametrised cases,
        but legitimate uses exist (skip-on-platform guards inside the body).

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Conditional logic in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag pytest test functions whose body contains ``if``/``elif``/``match`` branches.

        Stops at the first branching node per test (one finding per function is
        enough); ``for`` and ``while`` are handled by ``loop-in-test`` instead.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per test function containing branching control flow,
            anchored at the offending node.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.If | ast.Match):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} contains conditional logic — split into "
                            f"parametrised cases."
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
                            "Replace the branch with `@pytest.mark.parametrize` or two "
                            "separate test functions."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
                break  # one finding per test is enough
        return findings
