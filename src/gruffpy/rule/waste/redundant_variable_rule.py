"""``x = expr; return x`` pattern where ``x`` is not used elsewhere.

Strict shape: the LAST two statements of a function body are an ``Assign``
to a single ``Name`` followed by a ``Return`` of that same name, and the
name is referenced nowhere else in the function body. Comprehensions and
nested function scopes are scanned for the name; matches are conservative.
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


class RedundantVariableRule(Rule):
    ID = "waste.redundant-variable"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Redundant variable",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            body = node.body
            if len(body) < 2:
                continue
            assign = body[-2]
            ret = body[-1]
            if not (
                isinstance(assign, ast.Assign)
                and isinstance(ret, ast.Return)
                and len(assign.targets) == 1
                and isinstance(assign.targets[0], ast.Name)
                and isinstance(ret.value, ast.Name)
            ):
                continue
            name = assign.targets[0].id
            if ret.value.id != name:
                continue
            # Check the name is not referenced elsewhere in the body
            if _is_name_used_elsewhere(name, body[:-2]):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r}: variable {name!r} is assigned once "
                        f"and immediately returned; inline the expression."
                    ),
                    file_path=unit.file.display_path,
                    line=assign.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=ret.end_lineno,
                    symbol=symbol,
                    remediation=f"Replace `{name} = expr` + `return {name}` with `return expr`.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"variable": name},
                ),
            )
        return findings


def _is_name_used_elsewhere(name: str, statements: list[ast.stmt]) -> bool:
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and node.id == name:
                return True
    return False
