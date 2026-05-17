"""``size.average-function-length`` — classes with several long average functions strain readers."""

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

_MIN_METHODS = 3
MethodNode = ast.FunctionDef | ast.AsyncFunctionDef


class AverageFunctionLengthRule(Rule):
    ID = "size.average-function-length"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Average function length per class",
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
            _average_function_length_finding(
                unit, definition, node, methods, warning_threshold, error_threshold
            )
            for node, methods in _classes_with_long_average(unit.tree, warning_threshold)
        ]


def _classes_with_long_average(
    tree: ast.AST,
    warning_threshold: int | float,
) -> list[tuple[ast.ClassDef, list[MethodNode]]]:
    result: list[tuple[ast.ClassDef, list[MethodNode]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = _methods_for(node)
        if len(methods) >= _MIN_METHODS and _average_lines(methods) > warning_threshold:
            result.append((node, methods))
    return result


def _methods_for(node: ast.ClassDef) -> list[MethodNode]:
    return [
        child
        for child in node.body
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _average_lines(methods: list[MethodNode]) -> float:
    return sum(lines_for_size(method) for method in methods) / len(methods)


def _threshold_for(
    measured: int | float,
    warning_threshold: int | float,
    error_threshold: int | float,
) -> tuple[Severity, int | float]:
    if measured > error_threshold:
        return Severity.ERROR, error_threshold
    return Severity.WARNING, warning_threshold


def _average_function_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    methods: list[MethodNode],
    warning_threshold: int | float,
    error_threshold: int | float,
) -> Finding:
    avg = _average_lines(methods)
    severity, threshold = _threshold_for(avg, warning_threshold, error_threshold)
    symbol = qualified_symbol(node, parent_chain(node))
    rounded_avg = round(avg, 2)
    return Finding(
        rule_id=definition.id,
        message=(
            f"Class {symbol!r} averages {avg:.1f} lines per method "
            f"(over {len(methods)} methods), "
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
            "Shorten the typical method or split responsibilities; "
            "tall averages usually signal a god class."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "averageLines": rounded_avg,
            "measuredValue": rounded_avg,
            "methodCount": len(methods),
            "threshold": threshold,
            "thresholdDirection": "above",
            "thresholdType": severity.value,
        },
    )


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
