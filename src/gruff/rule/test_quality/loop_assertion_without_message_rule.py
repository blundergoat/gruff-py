"""``test-quality.loop-assertion-without-message`` — ``assert`` inside a loop with no message.

When an assertion inside a loop fails, the report tells you what — but not
which iteration. The rule fires when an assert nested in a for/while has no
message argument.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)


class LoopAssertionWithoutMessageRule(Rule):
    ID = "test-quality.loop-assertion-without-message"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Loop assertion without message",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            for loop in _iter_loops(fn):
                for inner in ast.walk(loop):
                    if not isinstance(inner, ast.Assert) or inner.msg is not None:
                        continue
                    parents = parent_chain(fn)
                    symbol = qualified_symbol(fn, parents)
                    findings.append(
                        Finding(
                            rule_id=definition.id,
                            message=(
                                f"Test {symbol!r} has an assertion inside a loop with no message."
                            ),
                            file_path=unit.file.display_path,
                            line=inner.lineno,
                            severity=definition.default_severity,
                            pillar=definition.pillar,
                            tier=definition.tier,
                            confidence=definition.confidence,
                            end_line=inner.end_lineno,
                            symbol=symbol,
                            remediation=(
                                "Add a message identifying the iteration, or split the "
                                "cases into a parametrised test."
                            ),
                            secondary_pillars=definition.secondary_pillars,
                            metadata={},
                        ),
                    )
                    break  # one finding per loop is enough
        return findings


def _iter_loops(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    return [n for n in walk_test_body(fn) if isinstance(n, ast.For | ast.AsyncFor | ast.While)]
