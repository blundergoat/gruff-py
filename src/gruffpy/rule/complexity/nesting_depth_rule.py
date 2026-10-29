"""Max nesting depth of control-flow blocks per function.

A control-flow block is any of: ``if``, ``for``, ``while``, ``try``,
``except`` (each handler counts as a level), ``match``, ``with``.
An ``elif`` chain stays at one level; an ``if`` nested inside an ``else`` opens another.

Lambdas reset depth (their body counts at 0). Nested function definitions
are scored independently.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._walks import FunctionLike, iter_functions
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size import _band
from gruffpy.rule.size._band import LIMIT_BAND_KEY, band_advice, banded_severity, limit_band, limit_in_force
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_NESTING_KINDS = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.With,
    ast.AsyncWith,
)


class NestingDepthRule(Rule):
    """Report functions whose control-flow nesting exceeds configured thresholds."""

    ID = "complexity.nesting-depth"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the nesting depth rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Nesting depth",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=6,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze function-like nodes for nesting depth findings.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with threshold settings.

        Returns:
            Findings for functions above the configured nesting threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            depth = nesting_depth_for(fn)
            threshold_match = settings.high_value_threshold_match(depth)
            band = limit_band(depth, limit_in_force(settings))
            if threshold_match is None:
                continue

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} nests {depth} levels deep, "
                        f"above the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=banded_severity(band, threshold_match.severity),
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=band_advice(band, _band.LOWER_FUNCTION, _band.SIMPLIFY_PATH),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "depth": depth,
                        "measuredValue": depth,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                        LIMIT_BAND_KEY: band,
                    },
                ),
            )
        return findings


def nesting_depth_for(fn: FunctionLike) -> int:
    """Return the maximum control-flow nesting depth inside a function body.

    Args:
        fn: Function, async function, or lambda node to score.

    Returns:
        Maximum nesting depth, or zero when there is no control flow.
    """
    if isinstance(fn, ast.Lambda):
        return 0
    body_max = 0
    for stmt in fn.body:
        body_max = max(body_max, _walk(stmt, current=0))
    return body_max


def _walk(node: ast.AST, current: int) -> int:
    """Return the deepest nesting depth reached within a node, given the depth of the block that encloses it.

    Function, class and lambda definitions stop the walk, so nested definitions add nothing to the enclosing function's depth. A node that is not a
    control-flow block passes the depth unchanged to its children; a control-flow block adds one level before its clauses are walked.

    Args:
        node: AST node to measure: a statement, or any child node reached while descending, such as an expression, keyword, comprehension, alias,
            operator, expression context or except handler.
        current: Nesting depth of the block that encloses node; zero for a top-level statement of the function body.

    Returns:
        The deepest depth reached within node, never less than current; a function, class or lambda definition returns current unchanged.
    """
    if _is_scope_boundary(node):
        return current
    if not isinstance(node, _NESTING_KINDS):
        return _deepest_child(node, current)

    nested = current + 1
    if isinstance(node, ast.Try):
        return _walk_try(node, nested)
    if isinstance(node, ast.Match):
        return _walk_match(node, nested)
    return _walk_body_and_orelse(node, nested)


def _is_scope_boundary(node: ast.AST) -> bool:
    """Decide whether a node opens a separate scope that the enclosing function's depth walk must not enter.

    Args:
        node: AST node met during the depth walk.

    Returns:
        True for a function, async function, class or lambda definition; False for any other node.
    """
    return isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda)


def _deepest_child(node: ast.AST, current: int) -> int:
    """Walk every direct child of a node that opens no level, keeping the enclosing depth unchanged.

    Args:
        node: Node that is neither a control-flow block nor a scope boundary, such as a plain statement or an expression.
        current: Nesting depth of the block that encloses node; each child is walked at this same depth.

    Returns:
        The deepest depth reached among the children, or current when node has no children or none goes deeper.
    """
    deepest = current
    for child in ast.iter_child_nodes(node):
        deepest = max(deepest, _walk(child, current))
    return deepest


def _walk_try(node: ast.Try, current: int) -> int:
    """Return the deepest depth across a try block's body, except handlers, else and finally clauses.

    Every clause is walked at the try's own level, so an except handler body sits at the same level as the try body rather than one deeper.

    Args:
        node: Try statement whose clauses are measured.
        current: Depth of the try block itself, already including its own level; the statements of every clause are walked at this depth.

    Returns:
        The deepest depth reached in any clause, or current when no clause goes deeper.
    """
    deepest = _deepest_in_statements(node.body, current)
    for handler in node.handlers:
        deepest = max(deepest, _deepest_in_statements(handler.body, current))
    deepest = max(deepest, _deepest_in_statements(node.orelse, current))
    return max(deepest, _deepest_in_statements(node.finalbody, current))


def _walk_match(node: ast.Match, current: int) -> int:
    """Return the deepest depth across every case body of a match statement.

    Args:
        node: Match statement whose case bodies are measured.
        current: Depth of the match statement itself, already including its own level; each case body is walked at this depth.

    Returns:
        The deepest depth reached in any case body, or current when no case body goes deeper.
    """
    deepest = current
    for case in node.cases:
        deepest = max(deepest, _deepest_in_statements(case.body, current))
    return deepest


def _walk_body_and_orelse(node: ast.AST, current: int) -> int:
    """Return the deepest depth across the body and else clause of an if, loop or with block.

    An if whose else clause holds a single if starting at the same column is treated as an elif: that branch is walked from the parent's enclosing
    depth, so once its own level is added it sits at the parent if's level instead of one deeper. An if written inside an indented else block keeps
    the extra level.

    Args:
        node: If, for, async for, while, with or async with statement; a missing or empty body or else clause counts as no statements.
        current: Depth of this block itself, already including its own level; its body and else statements are walked at this depth.

    Returns:
        The deepest depth reached in the body, the else clause or an elif chain, never less than current.
    """
    body = getattr(node, "body", []) or []
    orelse = getattr(node, "orelse", None) or []
    # An elif parses as an If inside its parent's orelse, but a reader sees a peer branch, not a level deeper. It starts
    # at its if's column; an if written inside an else block is indented, and stays one level deeper.
    is_elif = len(orelse) == 1 and isinstance(orelse[0], ast.If) and orelse[0].col_offset == getattr(node, "col_offset", -1)
    if isinstance(node, ast.If) and is_elif:
        return max(current, _deepest_in_statements(body, current), _walk(orelse[0], current - 1))
    return max(
        current,
        _deepest_in_statements(body, current),
        _deepest_in_statements(orelse, current),
    )


def _deepest_in_statements(statements: list[ast.stmt], current: int) -> int:
    """Return the deepest depth reached by any statement in one clause's statement list.

    Args:
        statements: Statements of one clause, such as a body, else, except handler, finally or case body; an empty list leaves the depth at current.
        current: Depth at which each statement is walked: the depth of the block that owns the clause, already including its own level.

    Returns:
        The deepest depth reached by any statement, or current when the list is empty or no statement goes deeper.
    """
    deepest = current
    for stmt in statements:
        deepest = max(deepest, _walk(stmt, current))
    return deepest


def _format_number(value: int | float) -> str:
    """Render a threshold for the finding message, dropping the decimal part of a whole-number value.

    Args:
        value: Threshold of the matched severity, given as an int or a float.

    Returns:
        The value as text: a non-integral float keeps its decimals, while any whole number is written without a decimal point, so 6.0 becomes 6.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
