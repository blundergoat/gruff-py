"""Cognitive complexity, SonarSource v1.4 (per ADR-003).

Increment rules:

- **B1** — +1 for each control-flow break: ``if``/``elif``/``else``, ``for``,
  ``while``, ``except`` handler, ``IfExp`` (ternary), ``match`` (the
  ``match`` itself; cases do NOT add another B1), recursion (``Call`` to
  the enclosing function by name).
- **B2** — additional ``+nesting_level`` for each control structure nested
  inside another control structure. Nesting resets on entry to a nested
  function/lambda body.
- **B3** — +1 per ``BoolOp`` node (each `and`/`or` sequence). Mixed-operator
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
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 15, "error": 30},
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
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Flatten nesting; replace nested conditionals with guard clauses "
                        "or dispatch tables; extract sub-procedures."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "cognitive": score,
                        "measuredValue": score,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
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
        for child in ast.iter_child_nodes(node):
            self.visit(child, nesting)

    def _visit_If(self, node: ast.If, nesting: int) -> None:
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
        self._visit_loop(node, nesting)

    def _visit_AsyncFor(self, node: ast.AsyncFor, nesting: int) -> None:
        self._visit_loop(node, nesting)

    def _visit_While(self, node: ast.While, nesting: int) -> None:
        self._visit_loop(node, nesting)

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While, nesting: int) -> None:
        self.score += 1 + nesting
        for stmt in node.body:
            self.visit(stmt, nesting + 1)
        if node.orelse:
            # `for ... else` / `while ... else` — count the else as +1 (no nesting)
            self.score += 1
            for stmt in node.orelse:
                self.visit(stmt, nesting + 1)
        # Walk the iter/test for BoolOps
        if isinstance(node, ast.For | ast.AsyncFor):
            self.visit(node.iter, nesting)
        else:
            self.visit(node.test, nesting)

    def _visit_Try(self, node: ast.Try, nesting: int) -> None:
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
        self.score += 1 + nesting
        # Walk children at nesting + 1
        self.visit(node.test, nesting + 1)
        self.visit(node.body, nesting + 1)
        self.visit(node.orelse, nesting + 1)

    def _visit_Match(self, node: ast.Match, nesting: int) -> None:
        self.score += 1 + nesting
        for case in node.cases:
            for stmt in case.body:
                self.visit(stmt, nesting + 1)
            if case.guard is not None:
                self.visit(case.guard, nesting + 1)
        self.visit(node.subject, nesting)

    def _visit_Lambda(self, node: ast.Lambda, nesting: int) -> None:
        # Nested lambda inside another function — the lambda body is a new
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
        self._visit_function_scope(node, nesting)

    def _visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef, nesting: int) -> None:
        self._visit_function_scope(node, nesting)

    def _visit_function_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        nesting: int,
    ) -> None:
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
        # Like nested functions — walk decorators + base expressions only.
        for decorator in node.decorator_list:
            self.visit(decorator, nesting)
        for base in node.bases:
            self.visit(base, nesting)

    def _visit_BoolOp(self, node: ast.BoolOp, nesting: int) -> None:
        self.score += 1
        for value in node.values:
            self.visit(value, nesting)

    def _visit_Call(self, node: ast.Call, nesting: int) -> None:
        if (
            self.self_name is not None
            and isinstance(node.func, ast.Name)
            and node.func.id == self.self_name
        ):
            self.score += 1
        for arg in node.args:
            self.visit(arg, nesting)
        for keyword in node.keywords:
            self.visit(keyword.value, nesting)


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
