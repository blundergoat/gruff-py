"""Single-statement wrapper that calls another function with the same args.

Matches: ``def foo(a, b): return bar(a, b)``. The wrapper adds no value
beyond renaming. Skip when:

- the wrapper has decorators (it likely changes call semantics);
- the wrapper has a *different* argument signature than the wrapped call;
- the wrapper IS a framework hook (registered route, etc.);
- the wrapper is abstract / overload / Protocol stub (handled by empty-function).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class OneLineFunctionRule(Rule):
    """Detect single-statement wrappers that forward all arguments to another call unchanged."""

    ID = "waste.one-line-function"

    def definition(self) -> RuleDefinition:
        """Describe the one-line-function rule as a medium-confidence advisory.

        Medium confidence: the heuristic only matches strict signature
        passthroughs, but decorators or framework hooks can still mean the
        wrapper is load-bearing in non-syntactic ways.

        Returns:
            Definition for the one-line-function rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="One-line function wrapper",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag functions whose body is just ``return f(...)`` forwarding the same args.

        The wrapper's parameter list must match the inner call one-for-one
        (positional, keyword, and ``*args``); otherwise the wrapper is doing
        real argument shaping work and is left alone.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per pure-passthrough wrapper function.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _one_line_function_finding(unit, definition, node)
            for node in _one_line_functions(unit.tree)
        ]


def _one_line_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and _is_one_line_passthrough(node)
    ]


def _is_one_line_passthrough(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if has_framework_decorator(node) or is_abstract_method(node) or is_overload_stub(node):
        return False
    if len(node.body) != 1:
        return False
    stmt = node.body[0]
    return (
        isinstance(stmt, ast.Return)
        and isinstance(stmt.value, ast.Call)
        and _has_passthrough_args(node, stmt.value)
    )


def _one_line_function_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {symbol!r} is a thin wrapper that forwards its arguments "
            "to a single call with no other work."
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
            "Inline the wrapped call or remove the wrapper if it's not "
            "needed for typing / dispatch / monkey-patching."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )


def _has_passthrough_args(fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    """True if *call*'s positional args and kwargs forward *fn*'s signature
    one-for-one (same names in same order; no extra args, no extra kwargs)."""
    args = fn.args
    expected_positional = [arg.arg for arg in args.posonlyargs + args.args]
    if expected_positional and expected_positional[0] in {"self", "cls"}:
        expected_positional = expected_positional[1:]
    return (
        _has_positional_passthrough(expected_positional, call)
        and _has_keyword_passthrough(args.kwonlyargs, call)
        and _has_matching_vararg_forward(args.vararg, call)
    )


def _has_positional_passthrough(expected_positional: list[str], call: ast.Call) -> bool:
    if len(call.args) != len(expected_positional):
        return False
    for name, passed in zip(expected_positional, call.args, strict=True):
        if not (isinstance(passed, ast.Name) and passed.id == name):
            return False
    return True


def _has_keyword_passthrough(expected_keywords: list[ast.arg], call: ast.Call) -> bool:
    expected_kw = [keyword.arg for keyword in expected_keywords]
    call_kw_names = [keyword.arg for keyword in call.keywords if keyword.arg is not None]
    if sorted(expected_kw) != sorted(call_kw_names):
        return False
    for keyword in call.keywords:
        if keyword.arg is None:
            return False
        if not (isinstance(keyword.value, ast.Name) and keyword.value.id == keyword.arg):
            return False
    return True


def _has_matching_vararg_forward(vararg: ast.arg | None, call: ast.Call) -> bool:
    return (vararg is not None) == any(isinstance(arg, ast.Starred) for arg in call.args)
