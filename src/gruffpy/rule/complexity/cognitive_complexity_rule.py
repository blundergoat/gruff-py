"""Cognitive complexity, SonarSource v1.4 (per ADR-003).

Increment rules:

- **B1** - +1 for each control-flow break: ``if``/``elif``/``else``, ``for``,
  ``while``, ``except`` handler, ``IfExp`` (ternary), ``match`` (the
  ``match`` itself; cases do NOT add another B1), recursion (``Call`` to
  the enclosing function by name).
- **B2** - additional ``+nesting_level`` for each control structure nested
  inside another control structure. Nesting resets on entry to a nested
  function/lambda body.
- **B3** - +1 per ``BoolOp`` node (each `and`/`or` sequence). Mixed-operator
  expressions parse as multiple ``BoolOp`` nodes (e.g. ``a and b or c`` is two).
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


class CognitiveComplexityRule(Rule):
    """Report functions whose cognitive complexity exceeds configured thresholds."""

    ID = "complexity.cognitive"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the cognitive complexity rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Cognitive complexity",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=30,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze function-like nodes for cognitive complexity findings.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with threshold settings.

        Returns:
            Findings for functions above the configured complexity threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            score = cognitive_for(fn)
            threshold_match = settings.high_value_threshold_match(score)
            band = limit_band(score, limit_in_force(settings))
            if threshold_match is None:
                continue

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has cognitive complexity {score}, "
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
                        "cognitive": score,
                        "measuredValue": score,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                        LIMIT_BAND_KEY: band,
                    },
                ),
            )
        return findings


_COGNITIVE_CACHE_ATTR = "_gruffpy_cognitive_complexity"


def cognitive_for(fn: FunctionLike) -> int:
    """Compute cognitive complexity for a function-like node per ADR-003.

    Args:
        fn: Function, async function, or lambda node to score.

    Returns:
        Cognitive complexity score for the node body.
    """
    cached = getattr(fn, _COGNITIVE_CACHE_ATTR, None)
    if isinstance(cached, int):
        return cached

    fn_name = getattr(fn, "name", None) if not isinstance(fn, ast.Lambda) else None
    counter = _Counter(self_name=fn_name)
    if isinstance(fn, ast.Lambda):
        counter.visit(fn.body, nesting=0)
    else:
        for stmt in fn.body:
            counter.visit(stmt, nesting=0)
    setattr(fn, _COGNITIVE_CACHE_ATTR, counter.score)
    return counter.score


class _Counter:
    """Stateful visitor that accumulates a cognitive complexity score."""

    def __init__(self, self_name: str | None) -> None:
        self.score = 0
        self.self_name = self_name

    def visit(self, node: ast.AST, nesting: int) -> None:
        """Dispatch a node to its cognitive-complexity visitor.

        Args:
            node: AST node to inspect.
            nesting: Current control-flow nesting depth.
        """
        handler = getattr(self, f"_visit_{type(node).__name__}", self._generic_visit)
        handler(node, nesting)

    def _generic_visit(self, node: ast.AST, nesting: int) -> None:
        """Visit every child of a node that has no dedicated handler, keeping the current nesting depth.

        Args:
            node: AST node whose type has no dedicated visitor method.
            nesting: Nesting depth passed unchanged to each child node.
        """
        for child in ast.iter_child_nodes(node):
            self.visit(child, nesting)

    def _visit_If(self, node: ast.If, nesting: int) -> None:
        """Score an if statement and its elif or else branches, then visit their bodies and conditions.

        The if adds 1 plus the nesting depth, and each elif and a final else add 1 with no nesting depth. Branch bodies are visited one level deeper
        and conditions at the current depth, so boolean operators in them still count.

        The visitor checks only node structure, which is identical for an elif and for an else block whose only statement is an if, so that shape is
        also scored as an elif.

        Args:
            node: If statement to score.
            nesting: Nesting depth of the if statement, added to its increment; branch bodies are visited one level deeper.
        """
        self.score += 1 + nesting  # B1 + B2
        for stmt in node.body:
            self.visit(stmt, nesting + 1)
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # `elif`: B1 only, no additional nesting penalty
                self.score += 1
                elif_node = node.orelse[0]
                # Treat the elif like an If but skip its own B1 (already added)
                for stmt in elif_node.body:
                    self.visit(stmt, nesting + 1)
                if elif_node.orelse:
                    self._visit_orelse(elif_node.orelse, nesting)
                self.visit(elif_node.test, nesting)
            else:
                self.score += 1
                for stmt in node.orelse:
                    self.visit(stmt, nesting + 1)
        self.visit(node.test, nesting)

    def _visit_orelse(self, orelse: list[ast.stmt], nesting: int) -> None:
        """Score the else branch of an elif, following any further elif links down the chain.

        An elif link and a final else each add 1 with no nesting depth; their bodies are visited one level deeper and each elif condition at the
        current depth.

        Args:
            orelse: Non-empty else-branch statements of an elif; a single if statement is treated as the next elif.
            nesting: Nesting depth of the if statement heading the chain.
        """
        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            # nested elif
            self.score += 1
            elif_node = orelse[0]
            for stmt in elif_node.body:
                self.visit(stmt, nesting + 1)
            if elif_node.orelse:
                self._visit_orelse(elif_node.orelse, nesting)
            self.visit(elif_node.test, nesting)
        else:
            self.score += 1
            for stmt in orelse:
                self.visit(stmt, nesting + 1)

    def _visit_For(self, node: ast.For, nesting: int) -> None:
        """Hand a for loop to the shared loop scoring.

        Args:
            node: For loop to score.
            nesting: Nesting depth of the loop.
        """
        self._visit_loop(node, nesting)

    def _visit_AsyncFor(self, node: ast.AsyncFor, nesting: int) -> None:
        """Hand an async for loop to the shared loop scoring.

        Args:
            node: Async for loop to score.
            nesting: Nesting depth of the loop.
        """
        self._visit_loop(node, nesting)

    def _visit_While(self, node: ast.While, nesting: int) -> None:
        """Hand a while loop to the shared loop scoring.

        Args:
            node: While loop to score.
            nesting: Nesting depth of the loop.
        """
        self._visit_loop(node, nesting)

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While, nesting: int) -> None:
        """Score a for, async for or while loop and its else clause, then visit the statements and iterable or condition.

        The loop adds 1 plus the nesting depth and a non-empty else clause adds 1 with no nesting depth; body and else statements are visited one
        level deeper. The iterable of a for loop or the condition of a while loop is visited at the current depth; a for loop's target is not visited.

        Args:
            node: Loop statement to score.
            nesting: Nesting depth of the loop, added to its increment.
        """
        self.score += 1 + nesting
        for stmt in node.body:
            self.visit(stmt, nesting + 1)
        if node.orelse:
            # `for ... else` / `while ... else` - count the else as +1 (no nesting)
            self.score += 1
            for stmt in node.orelse:
                self.visit(stmt, nesting + 1)
        # Walk the iter/test for BoolOps
        if isinstance(node, ast.For | ast.AsyncFor):
            self.visit(node.iter, nesting)
        else:
            self.visit(node.test, nesting)

    def _visit_Try(self, node: ast.Try, nesting: int) -> None:
        """Add 1 plus the nesting depth for each except handler of a try statement and visit all of its blocks.

        Handler bodies are visited one level deeper; the try body, else block and finally block are visited at the current depth.

        Args:
            node: Try statement to score.
            nesting: Nesting depth of the try statement, added to each handler's increment.
        """
        # The try itself is not a B1 in SonarSource v1.4 (no try-statement
        # increment); only handlers add B1 + B2.
        for stmt in node.body:
            self.visit(stmt, nesting)
        for handler in node.handlers:
            self.score += 1 + nesting
            for stmt in handler.body:
                self.visit(stmt, nesting + 1)
        for stmt in node.orelse:
            self.visit(stmt, nesting)
        for stmt in node.finalbody:
            self.visit(stmt, nesting)

    def _visit_IfExp(self, node: ast.IfExp, nesting: int) -> None:
        """Add 1 plus the nesting depth for a conditional expression and visit its three operands one level deeper.

        Args:
            node: Conditional expression to score.
            nesting: Nesting depth of the expression, added to its increment.
        """
        self.score += 1 + nesting
        # Walk children at nesting + 1
        self.visit(node.test, nesting + 1)
        self.visit(node.body, nesting + 1)
        self.visit(node.orelse, nesting + 1)

    def _visit_Match(self, node: ast.Match, nesting: int) -> None:
        """Add 1 plus the nesting depth for a match statement and visit its case bodies and guards one level deeper.

        Individual cases add no increment of their own, and the subject expression is visited at the current depth.

        Args:
            node: Match statement to score.
            nesting: Nesting depth of the match statement, added to its increment.
        """
        self.score += 1 + nesting
        for case in node.cases:
            for stmt in case.body:
                self.visit(stmt, nesting + 1)
            if case.guard is not None:
                self.visit(case.guard, nesting + 1)
        self.visit(node.subject, nesting)

    def _visit_Lambda(self, node: ast.Lambda, nesting: int) -> None:
        """Keep a nested lambda body out of the measured function's score, visiting only its default values.

        Args:
            node: Lambda nested inside the measured function.
            nesting: Nesting depth at which the default values are visited.
        """
        # Nested lambda inside another function - the lambda body is a new
        # scope; nesting resets to 0 for its body, but the *outer* function's
        # cognitive complexity does not include the lambda's interior (it
        # gets its own finding via iter_functions). Walk only the args
        # defaults at the outer nesting (for BoolOps in defaults).
        for default in node.args.defaults:
            self.visit(default, nesting)
        for kw_default in node.args.kw_defaults:
            if kw_default is not None:
                self.visit(kw_default, nesting)

    def _visit_FunctionDef(self, node: ast.FunctionDef, nesting: int) -> None:
        """Hand a nested function definition to the shared handling that keeps its body out of the score.

        Args:
            node: Function definition nested inside the measured function.
            nesting: Nesting depth at which the definition is reached.
        """
        self._visit_function_scope(node, nesting)

    def _visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef, nesting: int) -> None:
        """Hand a nested async function definition to the shared handling that keeps its body out of the score.

        Args:
            node: Async function definition nested inside the measured function.
            nesting: Nesting depth at which the definition is reached.
        """
        self._visit_function_scope(node, nesting)

    def _visit_function_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        nesting: int,
    ) -> None:
        """Keep a nested function body out of the measured function's score, visiting only decorators and defaults.

        Args:
            node: Function or async function definition nested inside the measured function.
            nesting: Nesting depth at which decorators and default values are visited.
        """
        # Nested function gets its own finding; walk only its decorator
        # expressions and default values at the outer nesting so BoolOps
        # there still count toward the outer function.
        for decorator in node.decorator_list:
            self.visit(decorator, nesting)
        for default in node.args.defaults:
            self.visit(default, nesting)
        for kw_default in node.args.kw_defaults:
            if kw_default is not None:
                self.visit(kw_default, nesting)

    def _visit_ClassDef(self, node: ast.ClassDef, nesting: int) -> None:
        """Keep a nested class body out of the measured function's score, visiting only decorators and base classes.

        Args:
            node: Class definition nested inside the measured function.
            nesting: Nesting depth at which decorators and base class expressions are visited.
        """
        # Like nested functions - walk decorators + base expressions only.
        for decorator in node.decorator_list:
            self.visit(decorator, nesting)
        for base in node.bases:
            self.visit(base, nesting)

    def _visit_BoolOp(self, node: ast.BoolOp, nesting: int) -> None:
        """Add 1 for a boolean operator sequence and visit its operands at the current nesting depth.

        Each BoolOp node adds 1, so a mixed expression such as a and b or c, which parses as two nodes, adds 2.

        Args:
            node: Boolean operation node to score.
            nesting: Nesting depth passed unchanged to the operands; it is not added to the increment.
        """
        self.score += 1
        for value in node.values:
            self.visit(value, nesting)

    def _visit_Call(self, node: ast.Call, nesting: int) -> None:
        """Add 1 when the callee is a bare name equal to the measured function's name, then visit the call arguments.

        The match is by name only: an attribute call such as self.name(...) is not counted even when it recurses, a method's bare call to a same-named
        module-level function is counted, and a measured lambda never scores recursion. The callee expression itself is not visited.

        Args:
            node: Call expression whose callee is compared with the measured function's name.
            nesting: Nesting depth passed unchanged to positional and keyword arguments.
        """
        if self.self_name is not None and isinstance(node.func, ast.Name) and node.func.id == self.self_name:
            self.score += 1
        for arg in node.args:
            self.visit(arg, nesting)
        for keyword in node.keywords:
            self.visit(keyword.value, nesting)


def _format_number(value: int | float) -> str:
    """Format a threshold for the finding message, showing whole-number floats without a trailing .0.

    Args:
        value: Threshold from the matched severity threshold.

    Returns:
        The value as text: a non-integer float keeps its decimal form, and any whole number is rendered as an integer.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
