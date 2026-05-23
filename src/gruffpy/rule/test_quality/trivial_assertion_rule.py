"""``test-quality.trivial-assertion`` - ``assert True``, ``assert 1``, etc.

Flags assertions whose left-hand side evaluates the same way every run:
literal truthy/falsy constants, ``assert not False``, and ``self.assertTrue(True)``.
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


class TrivialAssertionRule(Rule):
    """Detect always-true assertions like `assert True`, `assert 1`, or `self.assertTrue(True)`."""

    ID = "test-quality.trivial-assertion"

    def definition(self) -> RuleDefinition:
        """Describe the trivial-assertion rule as a high-confidence warning.

        High confidence because ``assert True``, ``assert 1``, and
        ``assert 1 == 1`` shapes are syntactically constant - there's no
        legitimate runtime case where they need to be in test code.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Trivial assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``assert`` statements whose test expression evaluates the same on every run.

        Catches three shapes: ``assert <constant>`` (bool/int/float
        literal), ``assert not <constant>`` (recursive unary-not), and
        ``assert <const> == <const>`` (compare between literals only).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per trivial assert.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Assert):
                    continue
                if not _is_trivial(node.test):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} has a trivial assertion that is always true/false."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=("Assert on the actual computed value or remove the line."),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
        return findings


def _is_trivial(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, bool | int | float)
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return _is_trivial(expr.operand)
    if isinstance(expr, ast.Compare):
        return all(isinstance(c, ast.Constant) for c in [expr.left, *expr.comparators])
    return False
