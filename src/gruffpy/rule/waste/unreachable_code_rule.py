"""Statements after a terminator (return/raise/continue/break) in the same block."""

import ast
from collections.abc import Callable, Iterator

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)
_SOURCE_NEEDLES: tuple[str, ...] = ("return", "raise", "continue", "break", "if", "while")
_BlockHandler = Callable[[ast.AST], Iterator[list[ast.stmt]]]


class UnreachableCodeRule(Rule):
    """Detect statements following a `return`, `raise`, `continue`, or `break` in the same block."""

    ID = "waste.unreachable-code"

    def definition(self) -> RuleDefinition:
        """Describe the unreachable-code rule as a high-confidence dead-code warning.

        High confidence because the rule only matches structural terminators
        (``return``, ``raise``, ``break``, ``continue``) and syntactically
        literal conditions; runtime-dependent branches stay clean because
        only ``ast.Constant`` tests qualify.

        Returns:
            Definition for the unreachable-code rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unreachable code",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag statements after a terminator, plus literal-condition dead branches.

        Walks every statement block (function bodies, if/else, loop bodies,
        try handlers, match cases) and reports the first statement after a
        ``return``/``raise``/``continue``/``break``. Also catches the dead
        side of ``if True:`` / ``if False:`` / ``while False:``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unreachable statement (at most one per terminator block).
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for block in _iter_blocks(unit.tree):
            for terminator_idx, stmt in enumerate(block):
                if isinstance(stmt, _TERMINATORS) and terminator_idx + 1 < len(block):
                    next_stmt = block[terminator_idx + 1]
                    terminator = type(stmt).__name__.lower()
                    findings.append(
                        Finding(
                            rule_id=definition.id,
                            message=(f"Statement on line {next_stmt.lineno} is unreachable: preceded by `{terminator}` on line {stmt.lineno}."),
                            file_path=unit.file.display_path,
                            line=next_stmt.lineno,
                            severity=definition.default_severity,
                            pillar=definition.pillar,
                            tier=definition.tier,
                            confidence=definition.confidence,
                            end_line=getattr(next_stmt, "end_lineno", None),
                            remediation=("Remove the unreachable code or move it before the terminator."),
                            secondary_pillars=definition.secondary_pillars,
                            metadata={
                                "terminator": terminator,
                                "terminatorLine": stmt.lineno,
                            },
                        ),
                    )
                    # Report only the first unreachable statement per block to
                    # avoid cascading noise.
                    break
        findings.extend(_literal_condition_findings(unit, definition))
        return findings


def _iter_blocks(tree: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over the statement lists exposed by the supported block handlers.

    Dispatch uses each node's exact type. A node without an entry in _BLOCK_HANDLERS contributes no statement list.

    Args:
        tree: AST root whose nodes are visited to find registered statement-block containers.

    Returns:
        Lazy iterator over the existing statement lists, including empty lists, in AST walk and handler order; lists are not copied.
    """
    for node in ast.walk(tree):
        handler = _BLOCK_HANDLERS.get(type(node))
        if handler is not None:
            yield from handler(node)


def _body_block(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over the body of a module, class or function.

    Args:
        node: Module, class, synchronous function or asynchronous function node whose body the caller will scan.

    Returns:
        Lazy iterator yielding the original body list once, even when it is empty.

    Raises:
        AssertionError: If iteration begins with a node outside the accepted module, class and function types.
    """
    assert isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module)
    yield node.body


def _body_and_orelse_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over the body and alternate branch of a conditional or loop.

    Args:
        node: If, For, AsyncFor or While node whose body and orelse lists the caller will scan.

    Returns:
        Lazy iterator yielding the original body list and then the original orelse list, including empty lists.

    Raises:
        AssertionError: If iteration begins with a node other than If, For, AsyncFor or While.
    """
    assert isinstance(node, ast.If | ast.For | ast.AsyncFor | ast.While)
    yield node.body
    yield node.orelse


def _try_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over a try statement's body, handlers, else and finally blocks.

    Args:
        node: Try node whose statement lists the caller will scan; TryStar nodes are not accepted.

    Returns:
        Lazy iterator yielding the original body, each handler body in order, orelse and finalbody lists, including empty lists.

    Raises:
        AssertionError: If iteration begins with a node that is not an ast.Try.
    """
    assert isinstance(node, ast.Try)
    yield node.body
    for handler in node.handlers:
        yield handler.body
    yield node.orelse
    yield node.finalbody


def _with_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over a synchronous or asynchronous context-manager body.

    Args:
        node: With or AsyncWith node whose body the caller will scan.

    Returns:
        Lazy iterator yielding the original body list once, even when it is empty.

    Raises:
        AssertionError: If iteration begins with a node other than With or AsyncWith.
    """
    assert isinstance(node, ast.With | ast.AsyncWith)
    yield node.body


def _match_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    """Iterate over the statement body of each match case.

    Args:
        node: Match node whose cases supply the statement lists to scan.

    Returns:
        Lazy iterator yielding each case's original body list in case order, including any empty body lists.

    Raises:
        AssertionError: If iteration begins with a node that is not an ast.Match.
    """
    assert isinstance(node, ast.Match)
    for case in node.cases:
        yield case.body


def _literal_condition_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
) -> list[Finding]:
    """Detect statements unreachable due to a syntactically-literal condition.

    Covers ``if <literal-false>:``, ``while <literal-false>:``, and the ``else``
    branch of ``if <literal-true>:``. Only ``ast.Constant`` tests qualify;
    dynamic names, calls, comparisons, and boolean operations stay clean so
    runtime-dependent conditions don't get flagged.

    Args:
        unit: Parsed source with a non-None AST; its display path is attached to each finding.
        definition: Rule metadata to attach to each unreachable-branch finding.

    Returns:
        One finding at the first statement of each non-empty literal-false if or while body, or literal-true if alternate branch; empty when none is
        found.

    Raises:
        AssertionError: If the source unit has no parsed AST.
    """
    assert unit.tree is not None
    findings: list[Finding] = []
    for node in ast.walk(unit.tree):
        if isinstance(node, ast.If):
            truthiness = _is_literal_truthy(node.test)
            if truthiness is False and node.body:
                findings.append(_literal_condition_finding(unit, definition, node.body[0], node, "literal-false-condition"))
            elif truthiness is True and node.orelse:
                findings.append(_literal_condition_finding(unit, definition, node.orelse[0], node, "literal-true-condition"))
        elif isinstance(node, ast.While):
            if _is_literal_truthy(node.test) is False and node.body:
                findings.append(_literal_condition_finding(unit, definition, node.body[0], node, "literal-false-condition"))
    return findings


def _is_literal_truthy(test: ast.expr) -> bool | None:
    """Return the truth value of *test* if it's a syntactic constant; else None.

    Args:
        test: Condition expression to classify; only an ast.Constant is evaluated for truthiness.

    Returns:
        The constant value's boolean truth value, or None when the expression is not an ast.Constant.
    """
    if not isinstance(test, ast.Constant):
        return None
    return bool(test.value)


def _literal_condition_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    stmt: ast.stmt,
    condition_node: ast.If | ast.While,
    cause: str,
) -> Finding:
    """Build a finding for the first statement in a branch rejected by a literal condition.

    Args:
        unit: Source unit supplying the finding display path.
        definition: Rule metadata supplying the finding identity, classification and confidence.
        stmt: First statement of the unreachable branch; its span locates the finding.
        condition_node: Enclosing If or While node; its type and line identify the condition in the message.
        cause: Caller-supplied reason code recorded in the finding metadata.

    Returns:
        Finding on the unreachable statement, with the reason code and condition line recorded in its metadata.
    """
    keyword = "if" if isinstance(condition_node, ast.If) else "while"
    return Finding(
        rule_id=definition.id,
        message=(f"Statement on line {stmt.lineno} is unreachable: the `{keyword}` on line {condition_node.lineno} has a literal condition."),
        file_path=unit.file.display_path,
        line=stmt.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(stmt, "end_lineno", None),
        remediation=("Remove the unreachable branch or replace the literal condition with the real check."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "cause": cause,
            "causeLine": condition_node.lineno,
        },
    )


_BLOCK_HANDLERS: dict[type[ast.AST], _BlockHandler] = {
    ast.Module: _body_block,
    ast.FunctionDef: _body_block,
    ast.AsyncFunctionDef: _body_block,
    ast.ClassDef: _body_block,
    ast.If: _body_and_orelse_blocks,
    ast.For: _body_and_orelse_blocks,
    ast.AsyncFor: _body_and_orelse_blocks,
    ast.While: _body_and_orelse_blocks,
    ast.Try: _try_blocks,
    ast.With: _with_blocks,
    ast.AsyncWith: _with_blocks,
    ast.Match: _match_blocks,
}
