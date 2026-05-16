"""``test-quality.mock-only-test`` — test never calls anything that isn't a mock.

Heuristic: every call in the test body either is a mock factory, an interaction
with a mock-bound name (``mock.return_value = ...``), or a framework assertion.
A test that never reaches into real code can't catch real bugs.
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
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    find_mock_bindings,
    is_assertion_call,
    is_mock_factory_call,
    test_functions,
    walk_test_body,
)


class MockOnlyTestRule(Rule):
    ID = "test-quality.mock-only-test"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Mock-only test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
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
            if _has_non_mock_call(fn, set(bindings)):
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Test {symbol!r} only exercises mocks — no real code is called.",
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Make sure the test calls into the SUT, not just into its mocked "
                        "collaborators."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _has_non_mock_call(fn: ast.FunctionDef | ast.AsyncFunctionDef, mock_names: set[str]) -> bool:
    for node in walk_test_body(fn):
        if not isinstance(node, ast.Call):
            continue
        if is_assertion_call(node) or is_mock_factory_call(node):
            continue
        target = call_target_name(node)
        if target is None:
            return True
        root = target.split(".")[0]
        if root in mock_names:
            continue
        if root in {"pytest", "unittest", "mock"}:
            continue
        return True
    return False
