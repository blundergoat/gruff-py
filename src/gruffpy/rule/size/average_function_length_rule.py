"""``size.average-function-length`` - classes with several long average functions strain readers."""

import ast

from gruffpy.config.rule_settings import RuleSettings
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
    """Flag classes (with at least 3 methods) whose mean method length exceeds the threshold."""

    ID = "size.average-function-length"

    def definition(self) -> RuleDefinition:
        """Describe the average-function-length rule with a configurable threshold (default 100).

        Returns:
            Definition under the size pillar; the metric is reported per class
            and only fires once at least 3 methods are present (avoiding noise
            on tiny classes).
        """
        return RuleDefinition(
            id=self.ID,
            name="Average function length per class",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 100, "error": 100},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per class whose mean method length crosses the threshold.

        Catches "god classes" that hide behind small methods *and* one giant
        one - the average reveals the bulk that per-method limits miss.
        Requires the class to have at least 3 methods.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per ``ClassDef`` whose mean method length is over
            threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = _active_high_threshold(settings)

        return [
            _average_function_length_finding(unit, definition, node, methods, settings)
            for node, methods in _classes_with_long_average(unit.tree, threshold)
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
        child for child in node.body if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
    ]


def _average_lines(methods: list[MethodNode]) -> float:
    return sum(lines_for_size(method) for method in methods) / len(methods)


def _average_function_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    methods: list[MethodNode],
    settings: RuleSettings,
) -> Finding:
    avg = _average_lines(methods)
    threshold_match = settings.high_value_threshold_match(avg)
    if threshold_match is None:
        raise ValueError("average function length finding requires a threshold match")
    symbol = qualified_symbol(node, parent_chain(node))
    rounded_avg = round(avg, 2)
    return Finding(
        rule_id=definition.id,
        message=(
            f"Class {symbol!r} averages {avg:.1f} lines per method "
            f"(over {len(methods)} methods), "
            f"above the {threshold_match.severity.value} threshold of "
            f"{_format_number(threshold_match.threshold)}."
        ),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=threshold_match.severity,
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
            "threshold": threshold_match.threshold,
            "thresholdDirection": "above",
            "thresholdType": threshold_match.severity.value,
        },
    )


def _active_high_threshold(settings: RuleSettings) -> int | float:
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
