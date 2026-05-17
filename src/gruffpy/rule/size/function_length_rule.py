"""``size.function-length`` — long functions are harder to test and safely modify."""

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
from gruffpy.rule.size._lines import lines_for_size, parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


class FunctionLengthRule(Rule):
    ID = "size.function-length"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Function length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 30, "error": 60},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        return [
            _function_length_finding(
                unit, definition, node, warning_threshold, error_threshold
            )
            for node in _long_functions(unit.tree, warning_threshold)
        ]


def _long_functions(tree: ast.AST, warning_threshold: int | float) -> list[FunctionNode]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda)
        and lines_for_size(node) > warning_threshold
    ]


def _threshold_for(
    measured: int | float,
    warning_threshold: int | float,
    error_threshold: int | float,
) -> tuple[Severity, int | float]:
    if measured > error_threshold:
        return Severity.ERROR, error_threshold
    return Severity.WARNING, warning_threshold


def _function_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    warning_threshold: int | float,
    error_threshold: int | float,
) -> Finding:
    line_count = lines_for_size(node)
    severity, threshold = _threshold_for(line_count, warning_threshold, error_threshold)
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {symbol!r} is {line_count} lines, "
            f"above the {severity.value} threshold of {_format_number(threshold)}."
        ),
        file_path=unit.file.display_path,
        line=_start_line(node),
        severity=severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Extract helper functions; split distinct steps into named units."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "lines": line_count,
            "measuredValue": line_count,
            "threshold": threshold,
            "thresholdDirection": "above",
            "thresholdType": severity.value,
        },
    )


def _start_line(node: FunctionNode) -> int:
    if isinstance(node, ast.Lambda):
        return node.lineno
    decorators = node.decorator_list
    if decorators:
        return min(node.lineno, *(decorator.lineno for decorator in decorators))
    return node.lineno


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
