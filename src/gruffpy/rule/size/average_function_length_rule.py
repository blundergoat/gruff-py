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
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol

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
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=100,
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
            for node, methods in _classes_with_long_average(unit.tree, code_line_numbers(unit.source, unit.tree), threshold)
        ]


def _classes_with_long_average(
    tree: ast.AST,
    code_lines: frozenset[int],
    warning_threshold: int | float,
) -> list[tuple[ast.ClassDef, list[MethodNode]]]:
    """Find every class, nested ones included, whose direct methods average more code lines than the threshold.

    A class qualifies only when it has at least three direct methods and its average method length is strictly above the threshold. Classes come back
    in ast.walk order.

    Args:
        tree: Parsed module to walk for class definitions at any depth.
        code_lines: The file's code line numbers, from code_line_numbers, used to measure each method.
        warning_threshold: Average method length a class must exceed to qualify; despite the name, the rule passes the value from
            _active_high_threshold, which may be a warning or an error severity threshold.

    Returns:
        Pairs of each qualifying class and its direct methods; an empty list when no class qualifies.
    """
    result: list[tuple[ast.ClassDef, list[MethodNode]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = _methods_for(node)
        if len(methods) >= _MIN_METHODS and _average_lines(methods, code_lines) > warning_threshold:
            result.append((node, methods))
    return result


def _methods_for(node: ast.ClassDef) -> list[MethodNode]:
    """Collect the methods defined directly in a class body, sync and async, in source order.

    Only top-level statements of the class body count, so functions nested inside methods, methods of nested classes, and functions defined under an
    if or try block in the class body are not included.

    Args:
        node: Class whose body is scanned.

    Returns:
        The class's direct function and async function definitions; an empty list when the body defines none.
    """
    return [child for child in node.body if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)]


def _average_lines(methods: list[MethodNode], code_lines: frozenset[int]) -> float:
    """Compute the mean number of code lines across a class's methods.

    Args:
        methods: Methods to measure; must be non-empty, which callers guarantee by requiring at least three methods.
        code_lines: The file's code line numbers, from code_line_numbers, so blank, comment, docstring and decorator lines are not counted.

    Returns:
        Average code lines per method as a float.
    """
    return sum(lines_for_size(method, code_lines) for method in methods) / len(methods)


def _average_function_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    methods: list[MethodNode],
    settings: RuleSettings,
) -> Finding:
    """Build the finding for a class whose average method length exceeds the configured threshold.

    The average is recomputed from the file's code lines and matched against the high-side threshold in settings, which supplies the reported severity
    and threshold. The message names the class's qualified symbol, the average to one decimal place, the method count, the threshold's severity and
    the threshold value. The finding spans the class from its class line to its end line, and its metadata records the average rounded to two decimals
    as averageLines and measuredValue, plus methodCount, threshold, thresholdDirection set to above, and thresholdType set to the severity.

    Args:
        unit: Analysed file that supplies the source, tree and display path for the finding.
        definition: This rule's definition, supplying the rule id, pillar, tier, confidence and secondary pillars.
        node: Class that crossed the threshold; its lines and qualified name locate the finding.
        methods: The class's direct methods, used for the average and the reported method count.
        settings: Resolved rule settings whose high-side threshold match decides the severity and threshold reported.

    Returns:
        The finding describing the class's average method length against the matched threshold.

    Raises:
        ValueError: When high_value_threshold_match returns no match, because settings carry no single severity threshold or the recomputed average
            does not exceed it.
    """
    avg = _average_lines(methods, code_line_numbers(unit.source, unit.tree))
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
        remediation=("Shorten the typical method or split responsibilities; tall averages usually signal a god class."),
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
    """Choose the average method length a class must exceed before the rule flags it.

    The settings' single severity threshold wins when set, as it is for this rule's registered default; otherwise the warning entry in thresholds is
    used, and numeric_threshold raises LookupError when that key is missing or not numeric.

    Args:
        settings: Resolved rule settings; a None severity_threshold means the warning threshold key is used instead.

    Returns:
        The single severity threshold's value, or the warning threshold when no single severity threshold is set.
    """
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def _format_number(value: int | float) -> str:
    """Render a threshold for the finding message without a trailing .0 on whole numbers.

    Args:
        value: Threshold value to render; a float with a fractional part keeps its decimals.

    Returns:
        The value as text, written as an integer when it has no fractional part.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
