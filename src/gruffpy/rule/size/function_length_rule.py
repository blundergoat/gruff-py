"""``size.function-length`` - long functions are harder to test and safely modify."""

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
from gruffpy.rule.size._lines import logical_line_numbers, logical_lines_for_size, parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


class FunctionLengthRule(Rule):
    """Flag ``def``, ``async def``, or ``lambda`` whose line count exceeds the threshold."""

    ID = "size.function-length"

    def definition(self) -> RuleDefinition:
        """Describe the function-length rule with a configurable line threshold (default 100).

        Returns:
            Definition under the size pillar; covers ``def``, ``async def``,
            and ``lambda`` nodes.
        """
        return RuleDefinition(
            id=self.ID,
            name="Function length",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=100,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per function whose body exceeds the configured line count.

        Length is the function's logical-line count from ``logical_lines_for_size``:
        a statement or compound-statement header counts once however many lines it
        spans, and blank lines, comments, docstrings and decorators are free. The finding's start line still includes decorators.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per ``FunctionDef``/``AsyncFunctionDef``/``Lambda``
            that crosses the threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = _active_high_threshold(settings)

        logical_lines = logical_line_numbers(unit.source, unit.tree)
        return [_function_length_finding(unit, definition, node, settings) for node in _long_functions(unit.tree, logical_lines, threshold)]


def _long_functions(tree: ast.AST, logical_lines: frozenset[int], warning_threshold: int | float) -> list[FunctionNode]:
    """Collect every function, async function and lambda in the tree whose logical-line count exceeds the threshold.

    The whole tree is walked, so nested functions and lambdas are checked as well as top-level ones.

    Args:
        tree: Parsed module tree to walk, including nested definitions.
        logical_lines: Line numbers that hold a logical line, used to count each function's size.
        warning_threshold: The active threshold; a function is kept only when its logical-line count is strictly greater.

    Returns:
        The over-threshold nodes in ast.walk order; an empty list when no function exceeds the threshold.
    """
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) and logical_lines_for_size(node, logical_lines) > warning_threshold
    ]


def _active_high_threshold(settings: RuleSettings) -> int | float:
    """Pick the active threshold that a function's logical-line count must exceed before the rule reports it.

    Args:
        settings: Resolved settings for this rule.

    Returns:
        The configured severity threshold's value when one is set, otherwise the warning threshold.
    """
    if settings.severity_threshold is not None:
        return settings.severity_threshold.threshold
    return settings.numeric_threshold("warning")


def _function_length_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    settings: RuleSettings,
) -> Finding:
    """Build the finding for one over-threshold function, reporting its logical-line count and the matched threshold.

    The logical-line count is recomputed from the unit's source and tree. The count is banded against the limit in force: in the lower band the
    severity drops to advisory and the remediation says not to add to the function, while in the upper band the finding keeps the matched threshold's
    severity and the remediation says to split the function. The finding starts on the earliest of the definition and decorator lines (the lambda's
    own line for a lambda) and ends on the node's end line.

    Args:
        unit: Parsed source file that contains the function; supplies the source, tree and display path.
        definition: This rule's definition, which supplies the rule id, pillar, tier, confidence and secondary pillars.
        node: The function, async function or lambda node that exceeded the active threshold.
        settings: Resolved settings for this rule, used to match the threshold and to find the limit in force.

    Returns:
        The finding, naming the function's qualified symbol, with metadata recording the line count, the matched threshold and its severity, the
        threshold direction above, and the limit band.

    Raises:
        ValueError: When the settings match no threshold for the function's logical-line count.
    """
    line_count = logical_lines_for_size(node, logical_line_numbers(unit.source, unit.tree))
    threshold_match = settings.high_value_threshold_match(line_count)
    band = limit_band(line_count, limit_in_force(settings))
    if threshold_match is None:
        raise ValueError("function length finding requires a threshold match")
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {symbol!r} is {line_count} lines, "
            f"above the {threshold_match.severity.value} threshold of "
            f"{_format_number(threshold_match.threshold)}."
        ),
        file_path=unit.file.display_path,
        line=_start_line(node),
        severity=banded_severity(band, threshold_match.severity),
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=band_advice(band, _band.LOWER_FUNCTION, _band.SPLIT_FUNCTION),
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


def _start_line(node: FunctionNode) -> int:
    """Return the line a function's finding starts on, so a decorated definition is reported from its first decorator.

    Args:
        node: The function, async function or lambda node being reported.

    Returns:
        The earliest of the def line and its decorator lines for a decorated definition, the def line for an undecorated one, and the lambda's own
        line for a lambda.
    """
    if isinstance(node, ast.Lambda):
        return node.lineno
    decorators = node.decorator_list
    if decorators:
        return min(node.lineno, *(decorator.lineno for decorator in decorators))
    return node.lineno


def _format_number(value: int | float) -> str:
    """Render a threshold for the finding message, dropping the decimal part of whole-number floats.

    Args:
        value: Threshold value to render.

    Returns:
        The value as text: a non-integral float keeps its decimal form, while an int or a whole-number float is written as an integer.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
