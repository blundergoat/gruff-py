"""``test-quality.trivial-snapshot`` — assertion compares against a large hardcoded literal.

Snapshot tests that pin against a literal tuple / list / dict of substantial
size are brittle: any production change updates the snapshot mechanically
without anyone reading the diff. The rule flags ``assert x == [...]`` (or
``snapshot.assert_match(...)``) with a literal of ≥10 elements.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)

_MIN_SIZE = 10


class TrivialSnapshotRule(Rule):
    ID = "test-quality.trivial-snapshot"

    def definition(self) -> RuleDefinition:
        """Describe the trivial-snapshot rule as a medium-confidence advisory.

        Medium confidence because a large literal in an assert is sometimes
        appropriate (e.g. a canonical encoding fixture); the rule reports
        the brittleness risk without enforcing.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Trivial snapshot assertion",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag asserts containing a list/tuple/set/dict literal with at least 10 elements.

        Stops at the first oversized literal per assert (one finding per
        statement); list/tuple/set use ``len(elts)``, dict uses
        ``len(keys)``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per assert whose test expression embeds a 10+
            element literal collection.
        """
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
