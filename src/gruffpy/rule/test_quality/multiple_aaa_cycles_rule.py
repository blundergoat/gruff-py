"""``test-quality.multiple-aaa-cycles`` - test executes multiple Arrange-Act-Assert cycles.

Heuristic: a test that interleaves assertions with **new function calls**
multiple times probably exercises multiple behaviours. A statement that only
unpacks an existing value (attribute access, subscript, rebinding, or a
literal/comprehension with no calls) does not end an assert block - it is
treated as continuation of the same assertion phase.
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
    """Detect tests whose assertions interleave with non-assertion work in multiple AAA cycles."""

    ID = "test-quality.multiple-aaa-cycles"

    def definition(self) -> RuleDefinition:
        """Describe the multiple-AAA-cycles rule as a low-confidence stylistic advisory.

        Low confidence reflects that identifying "cycles" by assert-block
        boundaries is still fuzzy even after restricting boundaries to
        call-containing statements - a deserialisation call between asserts
        can look like a new Act when it is just data unpacking.

        Returns:
            Definition with a ``maxCycles`` threshold defaulting to 2.
        """
        return RuleDefinition(
            id=self.ID,
            name="Multiple AAA cycles",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_thresholds={"maxCycles": 2},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests whose top-level body contains more than ``maxCycles`` assertion blocks.

        A cycle ends each time a non-assertion statement that contains a
        function call follows an assertion block; pure data-access
        statements (attribute, subscript, literal/dict-comp restructuring)
        do not end a cycle. The rule fires when the cycle count exceeds the
        configured threshold (default: more than 2).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``maxCycles``
                numeric threshold.

        Returns:
            One finding per test whose top-level cycle count exceeds the
            threshold.
        """
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

    A "cycle" ends when a call-containing statement follows an assertion
    block. Pure data-access statements (attribute, subscript, literal or
    comprehension restructuring with no function calls) are treated as
    continuation of the surrounding assert block, since they only unpack
    values for further assertions rather than introducing a new Act.
    """
    cycles = 0
    in_assert_block = False
    for stmt in fn.body:
        if _is_assertion_stmt(stmt):
            in_assert_block = True
            continue
        if in_assert_block and _has_call(stmt):
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


def _has_call(stmt: ast.stmt) -> bool:
    """Return whether *stmt* contains any function/method call expression.

    Nested function, class, and lambda bodies are skipped: a call inside
    a helper defined between asserts is not executed at that point and
    must not end the surrounding assert block.
    """

    class _CallFinder(ast.NodeVisitor):
        def __init__(self) -> None:
            self.found = False

        def visit_Call(self, _: ast.Call) -> None:  # noqa: N802 - ast visitor naming
            self.found = True

        def visit_FunctionDef(self, _: ast.FunctionDef) -> None:  # noqa: N802
            return

        def visit_AsyncFunctionDef(self, _: ast.AsyncFunctionDef) -> None:  # noqa: N802
            return

        def visit_ClassDef(self, _: ast.ClassDef) -> None:  # noqa: N802
            return

        def visit_Lambda(self, _: ast.Lambda) -> None:  # noqa: N802
            return

    finder = _CallFinder()
    finder.visit(stmt)
    return finder.found
