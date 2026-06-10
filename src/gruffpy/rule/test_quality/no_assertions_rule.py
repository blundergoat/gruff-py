"""``test-quality.no-assertions`` - test function with zero assertion-like calls.

Looks for ``assert`` statements, ``self.assertEqual`` / ``self.assertX`` calls,
``assert_*`` helper calls, and ``pytest.raises`` / ``pytest.warns`` contexts. A
test with none of these is probably testing nothing.
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
    installs_error_warnings_filter,
    is_assertion_call,
    is_catch_warnings_call,
    is_pytest_fixture_decorator,
    test_functions,
    walk_test_body,
)
from gruffpy.rule.test_quality._test_quality_scope import TestScope, TestScopeKind


class NoAssertionsRule(Rule):
    """Detect test functions containing zero assertion statements or helper calls."""

    ID = "test-quality.no-assertions"

    def definition(self) -> RuleDefinition:
        """Describe the no-assertions rule as a high-confidence warning.

        High confidence because a collected test with zero ``assert``
        statements, assertion helpers, framework assertions, AND
        ``pytest.raises``/``warns`` blocks is almost certainly verifying
        nothing.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Test without assertions",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag collected tests with no assertion statements, helpers, or raises/warns blocks.

        A test counts as having an assertion if any of these appear in its
        body: a bare ``assert`` statement, a framework assertion call, an
        ``assert_*`` helper call, or a ``with`` item whose context manager is an
        assertion call (``warnings.catch_warnings`` only when the block
        escalates warnings to errors). Pytest fixtures and conftest support
        functions are not collected tests for this rule.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per test function with zero detected assertions.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, scope in test_functions(unit):
            if _is_no_assertions_support_function(fn, scope):
                continue
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
        if isinstance(node, ast.Call) and _is_direct_assertion_call(node):
            return True
        if isinstance(node, ast.With) and _has_with_item_assertion(node):
            return True
    return _has_decorator_assertion_call(fn)


def _is_direct_assertion_call(node: ast.Call) -> bool:
    """``catch_warnings`` is excluded: alone it isolates warning state without verifying."""
    return is_assertion_call(node) and not is_catch_warnings_call(node)


def _has_with_item_assertion(node: ast.With) -> bool:
    for item in node.items:
        if not (isinstance(item.context_expr, ast.Call) and is_assertion_call(item.context_expr)):
            continue
        if is_catch_warnings_call(item.context_expr):
            if installs_error_warnings_filter(node):
                return True
            continue
        return True
    return False


def _has_decorator_assertion_call(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in fn.decorator_list:
        for node in ast.walk(decorator):
            if isinstance(node, ast.Call) and _is_direct_assertion_call(node):
                return True
    return False


def _is_no_assertions_support_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    scope: TestScope,
) -> bool:
    if scope.kind is TestScopeKind.CONFTEST:
        return True
    return any(is_pytest_fixture_decorator(decorator) for decorator in fn.decorator_list)
