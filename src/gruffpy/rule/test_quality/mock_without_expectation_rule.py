"""``test-quality.mock-without-expectation`` — mock created but no ``.assert_*`` call on it.

Catches the pattern where a mock is wired up but its interactions are never
verified. ``mock.return_value`` or ``mock.side_effect`` configuration alone is
not enough — the rule wants to see ``mock.assert_called`` / ``assert_called_with``
or similar.
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
    find_mock_bindings,
    test_functions,
    walk_test_body,
)


class MockWithoutExpectationRule(Rule):
    ID = "test-quality.mock-without-expectation"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Mock without expectation",
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
            bindings = find_mock_bindings(fn)
            if not bindings:
                continue
            verified = _verified_mocks(fn, set(bindings))
            unverified = sorted(set(bindings) - verified)
            if not unverified:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} has mocks with no .assert_* verification: {unverified}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "If the test relies on the mock, call ``mock.assert_called_with(...)`` "
                        "or similar. Otherwise drop the mock."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"unverified": list(unverified)},
                ),
            )
        return findings


def _verified_mocks(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str]) -> set[str]:
    verified: set[str] = set()
    for node in walk_test_body(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or not func.attr.startswith("assert_"):
            continue
        receiver_root = _root_name(func.value)
        if receiver_root in names:
            verified.add(receiver_root)
    return verified


def _root_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _root_name(node.value)
    return None
