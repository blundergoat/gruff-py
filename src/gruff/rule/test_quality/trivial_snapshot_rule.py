"""``test-quality.trivial-snapshot`` — assertion compares against a large hardcoded literal.

Snapshot tests that pin against a literal tuple / list / dict of substantial
size are brittle: any production change updates the snapshot mechanically
without anyone reading the diff. The rule flags ``assert x == [...]`` (or
``snapshot.assert_match(...)``) with a literal of ≥10 elements.
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

_MIN_SIZE = 10


class TrivialSnapshotRule(Rule):
    ID = "test-quality.trivial-snapshot"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Trivial snapshot assertion",
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
            for node in walk_test_body(fn):
                if not isinstance(node, ast.Assert):
                    continue
                literal = _large_literal_in(node.test)
                if literal is None:
                    continue
                parents = parent_chain(fn)
                symbol = qualified_symbol(fn, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Test {symbol!r} asserts against a large literal — brittle snapshot."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=(
                            "Assert on the salient invariant (length, key presence, type) "
                            "instead of pinning the full structure."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"literalSize": literal},
                    ),
                )
                break
        return findings


def _large_literal_in(expr: ast.expr) -> int | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.List | ast.Tuple | ast.Set) and len(node.elts) >= _MIN_SIZE:
            return len(node.elts)
        if isinstance(node, ast.Dict) and len(node.keys) >= _MIN_SIZE:
            return len(node.keys)
    return None
