"""``test-quality.tautological-type-assertion`` — ``isinstance(x, type(x))`` and friends.

Detects assertion-shaped expressions that are always true:

- ``assert isinstance(x, type(x))``
- ``assert type(x) is type(x)``
- ``assert x.__class__ is x.__class__``
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
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class TautologicalTypeAssertionRule(Rule):
    """Detect always-true assertions like `isinstance(x, type(x))` or `type(x) is type(x)`."""

    ID = "test-quality.tautological-type-assertion"

    def definition(self) -> RuleDefinition:
        """Describe the tautological-type-assertion rule as a medium-confidence advisory.

        Medium confidence because the rule's structural-equality check is
        intentionally shallow — it catches ``isinstance(x, type(x))`` and
        ``type(x) is type(x)`` but not semantically equivalent rewrites.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Tautological type assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``assert`` statements that assert always-true type identities.

        Detects two shapes: ``isinstance(obj, type(obj))`` where both
        operands are structurally identical, and ``Compare`` nodes with
        ``Is``/``Eq`` whose left and right are the same expression.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per ``assert`` whose ``test`` matches a tautological
            type identity.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Assert):
                    continue
                if not _is_tautology(node.test):
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} asserts a tautological type relation — always true."
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
                            "Assert on the expected behaviour, not the runtime type identity."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
        return findings


def _is_tautology(expr: ast.expr) -> bool:
    # Match always-true runtime type identity assertions.
    if isinstance(expr, ast.Call):
        target = call_target_name(expr)
        if target == "isinstance" and len(expr.args) == 2:
            obj, ty = expr.args
            if (
                isinstance(ty, ast.Call)
                and call_target_name(ty) == "type"
                and len(ty.args) == 1
                and _is_same_expr(obj, ty.args[0])
            ):
                return True
    # Match comparisons where both sides are the same type expression.
    return (
        isinstance(expr, ast.Compare)
        and len(expr.ops) == 1
        and isinstance(expr.ops[0], ast.Is | ast.Eq)
        and _is_same_expr(expr.left, expr.comparators[0])
    )


def _is_same_expr(a: ast.expr, b: ast.expr) -> bool:
    """Shallow structural equality — good enough for tautology detection."""
    if type(a) is not type(b):
        return False
    if isinstance(a, ast.Name) and isinstance(b, ast.Name):
        return a.id == b.id
    if isinstance(a, ast.Attribute) and isinstance(b, ast.Attribute):
        return a.attr == b.attr and _is_same_expr(a.value, b.value)
    if isinstance(a, ast.Call) and isinstance(b, ast.Call):
        return (
            _is_same_expr(a.func, b.func)
            and len(a.args) == len(b.args)
            and all(_is_same_expr(x, y) for x, y in zip(a.args, b.args, strict=False))
        )
    return False
