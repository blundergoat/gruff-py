"""``test-quality.multiple-aaa-cycles`` (opt-in) — test executes multiple Arrange-Act-Assert cycles.

Heuristic: a test that has assertions interleaved with non-assertion statements
multiple times probably exercises multiple behaviours. Default-off; users
explicitly enable when they want this stylistic enforcement.
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
)


class MultipleAaaCyclesRule(Rule):
    ID = "test-quality.multiple-aaa-cycles"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Multiple AAA cycles",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_enabled=False,
            default_thresholds={"maxCycles": 2},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("maxCycles")
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            cycles = _count_aaa_cycles(fn)
            if cycles <= threshold:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Test {symbol!r} runs {cycles} Arrange-Act-Assert cycles."),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Split each cycle into its own test for cleaner failure attribution."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"cycles": cycles, "threshold": threshold},
                ),
            )
        return findings


def _count_aaa_cycles(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Count assertion-block boundaries at the top level of *fn*'s body.

    A "cycle" ends when a non-assertion statement follows an assertion block.
    """
    cycles = 0
    in_assert_block = False
    for stmt in fn.body:
        if _is_assertion_stmt(stmt):
            in_assert_block = True
            continue
        if in_assert_block:
            cycles += 1
            in_assert_block = False
    if in_assert_block:
        cycles += 1
    return cycles


def _is_assertion_stmt(stmt: ast.stmt) -> bool:
    if isinstance(stmt, ast.Assert):
        return True
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and is_assertion_call(stmt.value)
    )
