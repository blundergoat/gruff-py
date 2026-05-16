"""``size.parameter-count`` — too many parameters make calls error-prone."""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class ParameterCountRule(Rule):
    ID = "size.parameter-count"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Parameter count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 5, "error": 8},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            count = _count_parameters(node, parents)
            if count <= warning_threshold:
                continue

            if count > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has {count} parameters, "
                        f"above the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Group related parameters into a dataclass or context object, "
                        "or split the function."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "parameters": count,
                        "threshold": threshold,
                        "thresholdType": severity.value,
                    },
                ),
            )

        return findings


def _count_parameters(fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> int:
    args = fn.args
    positional = list(args.posonlyargs) + list(args.args)
    if positional and _is_method(fn, parents):
        first_name = positional[0].arg
        if first_name in {"self", "cls"}:
            positional = positional[1:]
    count = len(positional) + len(args.kwonlyargs)
    if args.vararg is not None:
        count += 1
    if args.kwarg is not None:
        count += 1
    return count


def _is_method(_fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> bool:
    return any(isinstance(p, ast.ClassDef) for p in parents)


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
