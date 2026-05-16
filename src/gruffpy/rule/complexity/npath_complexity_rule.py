"""NPATH complexity per function.

NPATH (Nejmeh 1988) is the count of possible acyclic paths through a function.
Per the M03 spec: product of decision-point counts per linear segment; cap at
5000 to keep `metadata.npath` bounded.

Recurrences used:

- ``npath(block)`` = product of ``npath(stmt)`` for each ``stmt`` in ``block``.
- ``npath(linear_stmt)`` = 1.
- ``npath(if/elif/else)`` = sum of branch npaths + boolop count in condition.
- ``npath(for/while/AsyncFor)`` = npath(body) + condition boolops + 1.
- ``npath(try)`` = npath(body) + sum(npath(handler.body)) + 1.
- ``npath(match)`` = sum(npath(case.body)) + 1.
- ``npath(BoolOp)`` (when in a control condition) adds ``len(values)``.

Lambdas score npath on their single expression. Nested function/class
definitions are scored independently.
"""

import ast
from collections.abc import Iterable

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

_NPATH_CAP = 5000


class NPathComplexityRule(Rule):
    ID = "complexity.npath"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="NPATH complexity",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 200, "error": 500},
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
            np_raw = npath_for(fn)
            np_capped = min(np_raw, _NPATH_CAP)
            if np_capped <= warning_threshold:
                continue
            if np_capped > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            metadata: dict[str, int | float | bool | str] = {
                "npath": np_capped,
                "measuredValue": np_capped,
                "threshold": threshold,
                "thresholdDirection": "above",
                "thresholdType": severity.value,
            }
            if np_raw >= _NPATH_CAP:
                metadata["npathCapped"] = True
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has NPATH complexity {np_capped}"
                        f"{' (capped)' if np_raw >= _NPATH_CAP else ''}, "
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
                        "Break the function along independent decision points; "
                        "extract branches; consider polymorphism over conditionals."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata=metadata,
                ),
            )
        return findings


def npath_for(fn: FunctionLike) -> int:
    """Return NPATH for *fn*'s body. Caps internally at _NPATH_CAP * 10 to
    keep intermediate multiplications bounded (final value is capped by the
    rule)."""
    if isinstance(fn, ast.Lambda):
        return _npath_of([fn.body])
    return _npath_of(list(fn.body))


def _npath_of(stmts: Iterable[ast.AST]) -> int:
    total = 1
    for stmt in stmts:
        total *= _npath_stmt(stmt)
        if total >= _NPATH_CAP * 10:
            return _NPATH_CAP * 10
    return total


def _npath_stmt(node: ast.AST) -> int:
    if isinstance(node, ast.If):
        cond_paths = _condition_paths(node.test)
        then_paths = _npath_of(node.body)
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # elif chain
                else_paths = _npath_stmt(node.orelse[0])
            else:
                else_paths = _npath_of(node.orelse)
        else:
            else_paths = 1
        return cond_paths + then_paths + else_paths

    if isinstance(node, ast.For | ast.AsyncFor):
        return _npath_of(node.body) + _expression_boolops(node.iter) + 1

    if isinstance(node, ast.While):
        return _npath_of(node.body) + _condition_paths(node.test) + 1

    if isinstance(node, ast.Try):
        result = _npath_of(node.body)
        for handler in node.handlers:
            result += _npath_of(handler.body)
        for stmt in node.orelse:
            result *= _npath_stmt(stmt)
        for stmt in node.finalbody:
            result *= _npath_stmt(stmt)
        return result + 1

    if isinstance(node, ast.Match):
        total = 0
        for case in node.cases:
            total += _npath_of(case.body)
        return total + 1

    if isinstance(node, ast.With | ast.AsyncWith):
        return _npath_of(node.body)

    # Nested function / class — does not contribute to outer NPATH.
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return 1

    # Linear statement. Include boolops in the expression if any.
    return 1 + _expression_boolops(node)


def _condition_paths(test: ast.expr) -> int:
    """Number of boolean operator paths in a control-flow condition."""
    return max(1, _expression_boolops(test))


def _expression_boolops(node: ast.AST) -> int:
    """Count len(values)-style paths from BoolOps anywhere in *node*'s subtree."""
    paths = 0
    for child in ast.walk(node):
        if isinstance(child, ast.BoolOp):
            paths += len(child.values) - 1
    return paths


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
