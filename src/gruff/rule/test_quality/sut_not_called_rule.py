"""``test-quality.sut-not-called`` — test body has no call to a function under test.

Heuristic: scan the test body for calls whose target is NOT one of:

- ``assert*`` (test framework assertions)
- ``pytest.*`` / ``unittest.*``
- ``mock.*`` / ``Mock`` / ``MagicMock`` / ``patch`` (mock interactions)
- builtins like ``print``, ``len``, ``isinstance``, ``hasattr``

If no such call exists, the test isn't exercising the system under test.
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
from gruff.rule.security._security_node_helper import call_target_name
from gruff.rule.size._lines import parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import (
    is_assertion_call,
    test_functions,
    walk_test_body,
)

_FRAMEWORK_LEAVES: frozenset[str] = frozenset(
    {
        "raises",
        "warns",
        "approx",
        "param",
        "fixture",
        "parametrize",
        "mark",
        "skip",
        "skipif",
    }
)
_MOCK_LEAVES: frozenset[str] = frozenset(
    {
        "Mock",
        "MagicMock",
        "AsyncMock",
        "patch",
        "patch_object",
        "PropertyMock",
        "create_autospec",
        "return_value",
        "side_effect",
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_not_called",
        "reset_mock",
    }
)
_BUILTIN_LEAVES: frozenset[str] = frozenset(
    {"print", "len", "isinstance", "hasattr", "getattr", "setattr", "type", "id"}
)


class SutNotCalledRule(Rule):
    ID = "test-quality.sut-not-called"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="System under test never called",
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
            if _has_sut_call(fn):
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} never calls a non-framework, non-mock function "
                        f"— is the SUT exercised?"
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
                        "Make sure the test actually calls into the function or class "
                        "it claims to verify."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _has_sut_call(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in walk_test_body(fn):
        if not isinstance(node, ast.Call):
            continue
        if is_assertion_call(node):
            continue
        target = call_target_name(node)
        if target is None:
            return True  # Dynamic call — give the benefit of the doubt.
        leaf = target.split(".")[-1]
        root = target.split(".")[0]
        if root in {"pytest", "unittest", "mock"}:
            continue
        if leaf in _FRAMEWORK_LEAVES or leaf in _MOCK_LEAVES or leaf in _BUILTIN_LEAVES:
            continue
        if leaf.startswith("assert"):
            continue
        return True
    return False
