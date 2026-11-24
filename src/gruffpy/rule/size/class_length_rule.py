"""``size.class-length`` - large classes often mix too many responsibilities."""

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
from gruffpy.rule.size import _band
from gruffpy.rule.size._band import LIMIT_BAND_KEY, band_advice, banded_severity, limit_band, limit_in_force
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol


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
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=1000,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per class whose code-line count, including its header, exceeds the configured threshold.

        Args:
            unit: Source file to inspect; a missing AST yields no findings, and an existing AST's code-line cache may be populated.
            context: Rule execution context that supplies the threshold.

        Returns:
            Findings for over-threshold classes, anchored at the first decorator or the class line when undecorated; empty when none qualify.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = _active_high_threshold(settings)

        code_lines = code_line_numbers(unit.source, unit.tree)
        return [_class_length_finding(unit, definition, node, settings) for node in _long_classes(unit.tree, code_lines, threshold)]


def _long_classes(tree: ast.AST, code_lines: frozenset[int], warning_threshold: int | float) -> list[ast.ClassDef]:
    """Collect every class in the tree, nested classes included, whose code-line count exceeds the threshold.

    Args:
        tree: Parsed module to walk; every ClassDef found by ast.walk is measured.
        code_lines: The file's code line numbers from code_line_numbers, used to count each class's code lines.
        warning_threshold: Code-line count a class must strictly exceed to be collected; the caller passes the value from _active_high_threshold.

    Returns:
        Classes over the threshold in ast.walk order; empty when no class exceeds it.
    """
    return [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and lines_for_size(node, code_lines) > warning_threshold]


def _class_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    settings: RuleSettings,
) -> Finding:
    """Build the class-length finding for one over-threshold class, with its severity and advice set by limit band.

    The class's code lines are recounted from the unit's source and tree. The finding is anchored at the first decorator line when the class is
    decorated, otherwise at the class line, and ends at the class's end line.

    Args:
        unit: Source file supplying line counts and the finding path; its AST's code-line cache may be populated.
        definition: The rule's definition, supplying the rule id, pillar, tier, confidence and secondary pillars copied onto the finding.
        node: The class to report, already selected by _long_classes.
        settings: Effective rule settings that supply the matched threshold and the limit the code-line count is banded against.

    Returns:
        A class-span finding with the measured count, matched threshold and limit band recorded in metadata.
        The lower band uses advisory severity and do-not-grow advice; the upper band keeps the matched severity and uses split advice.

    Raises:
        ValueError: When settings.high_value_threshold_match returns no match for the class's code-line count, which happens when no single severity
            threshold is set or the count does not exceed it.
    """
    line_count = lines_for_size(node, code_line_numbers(unit.source, unit.tree))
    threshold_match = settings.high_value_threshold_match(line_count)
    band = limit_band(line_count, limit_in_force(settings))
    if threshold_match is None:
        raise ValueError("class length finding requires a threshold match")
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=f"Class {symbol!r} is {line_count} lines, above the limit of {_format_number(threshold_match.threshold)}.",
        file_path=unit.file.display_path,
        line=_start_line(node),
        severity=banded_severity(band, threshold_match.severity),
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=band_advice(band, _band.LOWER_CLASS, _band.SPLIT_CLASS),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "lines": line_count,
            "measuredValue": line_count,
            "threshold": threshold_match.threshold,
            "thresholdDirection": "above",
            "thresholdType": threshold_match.severity.value,
            LIMIT_BAND_KEY: band,
        },
    )


def _active_high_threshold(settings: RuleSettings) -> int | float:
    """Pick the code-line limit used to select long classes: the single severity threshold if set, else warning.

    Args:
        settings: Effective rule settings; a set severity_threshold takes precedence over the warning entry in the thresholds map.

    Returns:
        The single severity-threshold value when one is configured, otherwise the numeric warning threshold.

    Raises:
        LookupError: If no single severity threshold is set and the warning threshold is missing or nonnumeric.
    """
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def _start_line(node: ast.ClassDef) -> int:
    """Return the line a class finding is anchored at: the earliest decorator line, or the class line when undecorated.

    Args:
        node: The class whose anchor line is needed.

    Returns:
        The smallest of the class line and its decorator lines, so a decorated class is reported from its first decorator.
    """
    decorators = node.decorator_list
    if decorators:
        return min(node.lineno, *(decorator.lineno for decorator in decorators))
    return node.lineno


def _format_number(value: int | float) -> str:
    """Render a threshold for the finding message, dropping the decimal point from whole-number floats.

    Args:
        value: Threshold value to render; may be an int or a float.

    Returns:
        The value as text, so 1000.0 renders as 1000 while a fractional float keeps its decimal form.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
