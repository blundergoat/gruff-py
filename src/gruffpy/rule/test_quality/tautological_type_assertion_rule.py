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
    ID = "test-quality.tautological-type-assertion"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Tautological type assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
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
    # isinstance(x, type(x))
    if isinstance(expr, ast.Call):
        target = call_target_name(expr)
        if target == "isinstance" and len(expr.args) == 2:
            obj, ty = expr.args
            if (
                isinstance(ty, ast.Call)
                and call_target_name(ty) == "type"
                and len(ty.args) == 1
                and _same_expr(obj, ty.args[0])
            ):
                return True
    # type(x) is type(x) / x.__class__ is x.__class__
    return (
        isinstance(expr, ast.Compare)
        and len(expr.ops) == 1
        and isinstance(expr.ops[0], ast.Is | ast.Eq)
        and _same_expr(expr.left, expr.comparators[0])
    )


def _same_expr(a: ast.expr, b: ast.expr) -> bool:
    """Shallow structural equality — good enough for tautology detection."""
    if type(a) is not type(b):
        return False
    if isinstance(a, ast.Name) and isinstance(b, ast.Name):
        return a.id == b.id
    if isinstance(a, ast.Attribute) and isinstance(b, ast.Attribute):
        return a.attr == b.attr and _same_expr(a.value, b.value)
    if isinstance(a, ast.Call) and isinstance(b, ast.Call):
        return (
            call_target_name(a) == call_target_name(b)
            and len(a.args) == len(b.args)
            and all(_same_expr(x, y) for x, y in zip(a.args, b.args, strict=False))
        )
    return False
