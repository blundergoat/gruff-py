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
            Definition under the size pillar; covers functions, async functions and lambdas.
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
        """Emit one finding per function whose logical-line count exceeds the configured threshold.

        Successful tokenization counts definition headers and multiline statements once, excluding blanks, comments, docstrings and decorators.
        Tokenization failures fall back to physical code lines. Findings start at the first decorator when present.

        Args:
            unit: Source file to measure. Its AST can cache physical code lines and successfully tokenized logical starts.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per function, async function or lambda over threshold; an empty list if the tree is missing or none qualify.
            The measured count is at least one, even when no logical line starts inside the node's span.
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
        logical_lines: File line numbers where logical lines start, used to count the starts within each function's span.
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

    Raises:
        LookupError: If no single severity threshold is set and the warning threshold is missing or nonnumeric.
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
    """Build the finding for one over-threshold function, reporting its measured line count and the matched threshold.

    Lower-band findings are advisory with advice not to grow; upper-band findings keep the matched severity and advise splitting.
    The finding spans the earliest definition or decorator line through the node's end line; lambdas start on their own line.

    Args:
        unit: Source file supplying the text, tree and display path. Its AST can cache physical code lines and successfully tokenized logical starts.
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
        Integer text for integers and finite whole-number floats. Other floats use their usual Python text.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
