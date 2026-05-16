"""``test-quality.no-assertions`` — test function with zero assertion-like calls.

Looks for ``assert`` statements, ``self.assertEqual`` / ``self.assertX`` calls,
and ``pytest.raises`` / ``pytest.warns`` contexts. A test with none of these is
probably testing nothing.
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
    is_assertion_call,
    test_functions,
    walk_test_body,
)


class NoAssertionsRule(Rule):
    ID = "test-quality.no-assertions"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Test without assertions",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            if _has_any_assertion(fn):
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Test {symbol!r} contains no assertions.",
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Assert the expected behaviour, raise on the unexpected, or "
                        "delete the test if it's not exercising anything."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _has_any_assertion(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in walk_test_body(fn):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call) and is_assertion_call(node):
            return True
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and is_assertion_call(item.context_expr):
                    return True
    return False
