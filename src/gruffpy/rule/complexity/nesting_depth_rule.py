"""Max nesting depth of control-flow blocks per function.

A control-flow block is any of: ``if``, ``for``, ``while``, ``try``,
``except`` (each handler counts as a level), ``match``, ``with``.

Lambdas reset depth (their body counts at 0). Nested function definitions
are scored independently.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._walks import FunctionLike, iter_functions
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_NESTING_KINDS = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.With,
    ast.AsyncWith,
)


class NestingDepthRule(Rule):
    ID = "complexity.nesting-depth"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Nesting depth",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 4, "error": 6},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            depth = nesting_depth_for(fn)
            if depth <= warning_threshold:
                continue
            if depth > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} nests {depth} levels deep, "
                        f"above the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Flatten with guard clauses, early returns, or extracted helpers."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "depth": depth,
                        "measuredValue": depth,
                        "threshold": threshold,
                        "thresholdDirection": "above",
                        "thresholdType": severity.value,
                    },
                ),
            )
        return findings


def nesting_depth_for(fn: FunctionLike) -> int:
    """Return the maximum nesting depth inside *fn*'s body. 0 if no control flow."""
    if isinstance(fn, ast.Lambda):
        return 0
    body_max = 0
    for stmt in fn.body:
        body_max = max(body_max, _walk(stmt, current=0))
    return body_max


def _walk(node: ast.AST, current: int) -> int:
    if _is_scope_boundary(node):
        return current
    if not isinstance(node, _NESTING_KINDS):
        return _deepest_child(node, current)

    nested = current + 1
    if isinstance(node, ast.Try):
        return _walk_try(node, nested)
    if isinstance(node, ast.Match):
        return _walk_match(node, nested)
    return _walk_body_and_orelse(node, nested)


def _is_scope_boundary(node: ast.AST) -> bool:
    return isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda)


def _deepest_child(node: ast.AST, current: int) -> int:
    deepest = current
    for child in ast.iter_child_nodes(node):
        deepest = max(deepest, _walk(child, current))
    return deepest


def _walk_try(node: ast.Try, current: int) -> int:
    deepest = _deepest_in_statements(node.body, current)
    for handler in node.handlers:
        deepest = max(deepest, _deepest_in_statements(handler.body, current))
    deepest = max(deepest, _deepest_in_statements(node.orelse, current))
    return max(deepest, _deepest_in_statements(node.finalbody, current))


def _walk_match(node: ast.Match, current: int) -> int:
    deepest = current
    for case in node.cases:
        deepest = max(deepest, _deepest_in_statements(case.body, current))
    return deepest


def _walk_body_and_orelse(node: ast.AST, current: int) -> int:
    body = getattr(node, "body", []) or []
    orelse = getattr(node, "orelse", None) or []
    return max(
        current,
        _deepest_in_statements(body, current),
        _deepest_in_statements(orelse, current),
    )


def _deepest_in_statements(statements: list[ast.stmt], current: int) -> int:
    deepest = current
    for stmt in statements:
        deepest = max(deepest, _walk(stmt, current))
    return deepest


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
