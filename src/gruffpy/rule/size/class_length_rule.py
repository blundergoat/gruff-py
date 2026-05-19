"""``size.class-length`` — large classes often mix too many responsibilities."""

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


class ClassLengthRule(Rule):
    """Flag classes whose body line count exceeds the threshold (default 1000)."""

    ID = "size.class-length"

    def definition(self) -> RuleDefinition:
        """Describe the class-length rule with a configurable line threshold (default 1000).

        Returns:
            Definition under the size pillar; class span includes nested
            methods and class-level statements.
        """
        return RuleDefinition(
            id=self.ID,
            name="Class length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 1000, "error": 1000},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per class whose body exceeds the configured line count.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per ``ClassDef`` over threshold, anchored at the
            class definition line (decorators included).
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = _active_high_threshold(settings)

        return [
            _class_length_finding(unit, definition, node, settings)
            for node in _long_classes(unit.tree, threshold)
        ]


def _long_classes(tree: ast.AST, warning_threshold: int | float) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and lines_for_size(node) > warning_threshold
    ]


def _class_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    settings: RuleSettings,
) -> Finding:
    line_count = lines_for_size(node)
    threshold_match = settings.high_value_threshold_match(line_count)
    if threshold_match is None:
        raise ValueError("class length finding requires a threshold match")
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Class {symbol!r} is {line_count} lines, "
            f"above the {threshold_match.severity.value} threshold of "
            f"{_format_number(threshold_match.threshold)}."
        ),
        file_path=unit.file.display_path,
        line=_start_line(node),
        severity=threshold_match.severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=(
            "Split the class along responsibility boundaries; "
            "extract collaborators or value objects."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "lines": line_count,
            "measuredValue": line_count,
            "threshold": threshold_match.threshold,
            "thresholdDirection": "above",
            "thresholdType": threshold_match.severity.value,
        },
    )


def _active_high_threshold(settings: RuleSettings) -> int | float:
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def _start_line(node: ast.ClassDef) -> int:
    decorators = node.decorator_list
    if decorators:
        return min(node.lineno, *(decorator.lineno for decorator in decorators))
    return node.lineno


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
