"""``test-quality.exception-type-only`` - ``pytest.raises(Exception)`` without ``match=``.

Catching just the type doesn't verify *which* error was raised. The rule fires
on ``pytest.raises`` / ``pytest.warns`` contexts that omit the ``match`` argument
when catching a wide type (``Exception`` / ``BaseException``).
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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    is_assertion_call,
    test_functions,
    walk_test_body,
)


class ExceptionTypeOnlyRule(Rule):
    """Detect exception expectations that check neither a match nor captured error details."""

    ID = "test-quality.exception-type-only"

    def definition(self) -> RuleDefinition:
        """Describe the exception-type-only rule as a medium-confidence advisory.

        Medium confidence because catching ``Exception`` without ``match=`` is
        sometimes intentional (you genuinely don't care about the message),
        but more often hides which error actually fired.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Exception type-only assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``pytest.raises``/``pytest.warns`` catching ``Exception`` without ``match=``.

        Only fires when the caught type is wide (``Exception`` or
        ``BaseException``, by name or attribute) AND no ``match`` keyword is
        provided - narrow types like ``ValueError`` are presumed intentional.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per type-only wide-exception assertion.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [_exception_type_only_finding(unit, definition, fn, node) for fn, node in _type_only_exception_assertions(unit)]


def _type_only_exception_assertions(
    unit: AnalysisUnit,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Call]]:
    findings: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.Call]] = []
    for fn, _scope in test_functions(unit):
        for node in walk_test_body(fn):
            if isinstance(node, ast.Call) and _is_type_only_exception_assertion(node) and not _has_captured_detail_check(fn, node):
                findings.append((fn, node))
    return findings


def _has_captured_detail_check(fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    for statement in walk_test_body(fn):
        if not isinstance(statement, ast.With):
            continue
        for item in statement.items:
            if item.context_expr is call and isinstance(item.optional_vars, ast.Name):
                return _has_later_detail_assertion(fn, statement, item.optional_vars.id)
    return False


def _has_later_detail_assertion(fn: ast.FunctionDef | ast.AsyncFunctionDef, context: ast.With, capture: str) -> bool:
    end_line = context.end_lineno or context.lineno
    nodes = list(walk_test_body(fn))
    for node in nodes:
        if not isinstance(node, ast.Assert | ast.Call) or node.lineno <= end_line:
            continue
        if isinstance(node, ast.Call) and not is_assertion_call(node):
            continue
        if any(
            isinstance(other, ast.Name) and other.id == capture and isinstance(other.ctx, ast.Store) and end_line < other.lineno <= node.lineno
            for other in nodes
        ):
            continue
        if any(_is_captured_detail(value, capture) for value in ast.walk(node)):
            return True
    return False


def _is_captured_detail(node: ast.AST, capture: str) -> bool:
    if isinstance(node, ast.Call) and call_target_name(node) in {"str", "repr"} and node.args:
        return _is_captured_value(node.args[0], capture)
    if isinstance(node, ast.Attribute) and node.attr in {"args", "msg", "message", "code", "errno", "reason"}:
        return _is_captured_value(node.value, capture)
    return False


def _is_captured_value(node: ast.AST, capture: str) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "value" and isinstance(node.value, ast.Name) and node.value.id == capture


def _is_type_only_exception_assertion(node: ast.Call) -> bool:
    target = call_target_name(node)
    if target is None or target.split(".")[-1] not in {"raises", "warns"}:
        return False
    if not node.args or not _is_wide_exception(node.args[0]):
        return False
    return call_keyword(node, "match") is None


def _exception_type_only_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    node: ast.Call,
) -> Finding:
    symbol = qualified_symbol(fn, parent_chain(fn))
    return Finding(
        rule_id=definition.id,
        message=(f"Test {symbol!r} catches a wide exception without `match=`."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Narrow the exception type or add `match='expected substring'` to bind the assertion to the message."),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )


def _is_wide_exception(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id in {"Exception", "BaseException"}:
        return True
    return isinstance(node, ast.Attribute) and node.attr in {"Exception", "BaseException"}
