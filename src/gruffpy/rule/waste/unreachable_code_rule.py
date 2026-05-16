"""Statements after a terminator (return/raise/continue/break) in the same block."""

import ast
from collections.abc import Iterator

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
        if isinstance(
            node,
            ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module,
        ):
            if hasattr(node, "body") and isinstance(node.body, list):
                yield node.body
        elif isinstance(node, ast.If | ast.For | ast.AsyncFor | ast.While):
            yield node.body
            yield node.orelse
        elif isinstance(node, ast.Try):
            yield node.body
            for handler in node.handlers:
                yield handler.body
            yield node.orelse
            yield node.finalbody
        elif isinstance(node, ast.With | ast.AsyncWith):
            yield node.body
        elif isinstance(node, ast.Match):
            for case in node.cases:
                yield case.body
