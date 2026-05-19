"""``x = expr; return x`` pattern where ``x`` is not used elsewhere.

Strict shape: the LAST two statements of a function body are an ``Assign``
to a single ``Name`` followed by a ``Return`` of that same name, and the
name is referenced nowhere else in the function body. Comprehensions and
nested function scopes are scanned for the name; matches are conservative.
"""

import ast
from typing import NamedTuple

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


class _RedundantReturn(NamedTuple):
    function: ast.FunctionDef | ast.AsyncFunctionDef
    assign: ast.Assign
    ret: ast.Return
    name: str


class RedundantVariableRule(Rule):
    ID = "waste.redundant-variable"

    def definition(self) -> RuleDefinition:
        """Describe the redundant-variable rule as a high-confidence advisory.

        Advisory because the pattern (``x = expr; return x``) is stylistic
        and sometimes preserved as a debugger-aid binding. High confidence
        because the AST shape is precise and the unused-elsewhere check
        eliminates the only common false-positive.

        Returns:
            Definition for the redundant-variable rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Redundant variable",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag the ``x = expr; return x`` shape when ``x`` is unused elsewhere.

        Detection is restricted to the last two statements of a function and
        ignores cases where the temporary is referenced earlier in the body
        (a real local), so debugger-aid bindings stay clean.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per function ending in a redundant assign-and-return.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _redundant_variable_finding(unit, definition, candidate)
            for candidate in _redundant_variables(unit.tree)
        ]


def _redundant_variables(tree: ast.AST) -> list[_RedundantReturn]:
    findings: list[_RedundantReturn] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        candidate = _redundant_variable(node)
        if candidate is not None:
            findings.append(candidate)
    return findings


def _redundant_variable(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> _RedundantReturn | None:
    body = node.body
    if len(body) < 2:
        return None
    assign = body[-2]
    ret = body[-1]
    if not _has_redundant_return_shape(assign, ret):
        return None
    assert isinstance(assign, ast.Assign)
    assert isinstance(assign.targets[0], ast.Name)
    assert isinstance(ret, ast.Return)
    name = assign.targets[0].id
    if _is_name_used_elsewhere(name, body[:-2]):
        return None
    return _RedundantReturn(function=node, assign=assign, ret=ret, name=name)


def _has_redundant_return_shape(assign: ast.stmt, ret: ast.stmt) -> bool:
    if not isinstance(assign, ast.Assign) or not isinstance(ret, ast.Return):
        return False
    if len(assign.targets) != 1:
        return False
    if not isinstance(assign.targets[0], ast.Name) or not isinstance(ret.value, ast.Name):
        return False
    return ret.value.id == assign.targets[0].id


def _redundant_variable_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _RedundantReturn,
) -> Finding:
    symbol = qualified_symbol(candidate.function, parent_chain(candidate.function))
    name = candidate.name
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {symbol!r}: variable {name!r} is assigned once "
            f"and immediately returned; inline the expression."
        ),
        file_path=unit.file.display_path,
        line=candidate.assign.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.ret.end_lineno,
        symbol=symbol,
        remediation=f"Replace `{name} = expr` + `return {name}` with `return expr`.",
        secondary_pillars=definition.secondary_pillars,
        metadata={"variable": name},
    )


def _is_name_used_elsewhere(name: str, statements: list[ast.stmt]) -> bool:
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and node.id == name:
                return True
    return False
