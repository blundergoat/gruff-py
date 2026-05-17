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
_BlockHandler = Callable[[ast.AST], Iterator[list[ast.stmt]]]


class UnreachableCodeRule(Rule):
    ID = "waste.unreachable-code"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unreachable code",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
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
                            message=(
                                f"Statement on line {next_stmt.lineno} is unreachable: "
                                f"preceded by `{terminator}` on line {stmt.lineno}."
                            ),
                            file_path=unit.file.display_path,
                            line=next_stmt.lineno,
                            severity=definition.default_severity,
                            pillar=definition.pillar,
                            tier=definition.tier,
                            confidence=definition.confidence,
                            end_line=getattr(next_stmt, "end_lineno", None),
                            remediation=(
                                "Remove the unreachable code or move it before the terminator."
                            ),
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
        return findings


def _iter_blocks(tree: ast.AST) -> Iterator[list[ast.stmt]]:
    """Yield every list[stmt] block in *tree* — function bodies, if/else/elif,
    for/while bodies + orelse, try body + handlers + orelse + finalbody,
    match cases, with/AsyncWith bodies."""
    for node in ast.walk(tree):
        handler = _BLOCK_HANDLERS.get(type(node))
        if handler is not None:
            yield from handler(node)


def _body_block(node: ast.AST) -> Iterator[list[ast.stmt]]:
    assert isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module)
    yield node.body


def _body_and_orelse_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    assert isinstance(node, ast.If | ast.For | ast.AsyncFor | ast.While)
    yield node.body
    yield node.orelse


def _try_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    assert isinstance(node, ast.Try)
    yield node.body
    for handler in node.handlers:
        yield handler.body
    yield node.orelse
    yield node.finalbody


def _with_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    assert isinstance(node, ast.With | ast.AsyncWith)
    yield node.body


def _match_blocks(node: ast.AST) -> Iterator[list[ast.stmt]]:
    assert isinstance(node, ast.Match)
    for case in node.cases:
        yield case.body


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
