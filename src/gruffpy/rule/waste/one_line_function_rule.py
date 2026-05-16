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
    ID = "waste.one-line-function"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="One-line function wrapper",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if has_framework_decorator(node):
                continue
            if is_abstract_method(node) or is_overload_stub(node):
                continue
            body = node.body
            if len(body) != 1:
                continue
            stmt = body[0]
            if not isinstance(stmt, ast.Return) or not isinstance(stmt.value, ast.Call):
                continue
            call = stmt.value
            if not _args_match_passthrough(node, call):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
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
                ),
            )
        return findings


def _args_match_passthrough(fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    """True if *call*'s positional args and kwargs forward *fn*'s signature
    one-for-one (same names in same order; no extra args, no extra kwargs)."""
    args = fn.args
    expected_positional = [arg.arg for arg in args.posonlyargs + args.args]
    # Methods: ignore the implicit `self`/`cls` if present (still forwarded).
    if expected_positional and expected_positional[0] in {"self", "cls"}:
        expected_positional = expected_positional[1:]

    if len(call.args) != len(expected_positional):
        return False
    for name, passed in zip(expected_positional, call.args, strict=True):
        if not (isinstance(passed, ast.Name) and passed.id == name):
            return False

    expected_kw = [k.arg for k in args.kwonlyargs]
    call_kw_names = [k.arg for k in call.keywords if k.arg is not None]
    if sorted(expected_kw) != sorted(call_kw_names):
        return False
    for k in call.keywords:
        if k.arg is None:
            return False
        if not (isinstance(k.value, ast.Name) and k.value.id == k.arg):
            return False

    has_vararg = args.vararg is not None
    call_starred = any(isinstance(a, ast.Starred) for a in call.args)
    return has_vararg == call_starred
