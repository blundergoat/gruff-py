"""``test-quality.no-assertions`` - test function with zero assertion-like calls.

Looks for ``assert`` statements, ``self.assertEqual`` / ``self.assertX`` calls,
``assert_*`` helper calls, and ``pytest.raises`` / ``pytest.warns`` contexts,
including direct and aliased imports. A test with none of these is probably
testing nothing.
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
    has_error_warnings_filter,
    is_assertion_call,
    is_catch_warnings_call,
    is_pytest_fixture_decorator,
    test_functions,
    walk_test_body,
)
from gruffpy.rule.test_quality._test_quality_scope import TestScope, TestScopeKind

_PYTEST_ASSERTION_HELPERS: frozenset[str] = frozenset(
    {"raises", "warns", "deprecated_call", "approx", "fail"}
)


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
        # Sources without an AST cannot contain a collected Python test.
        if unit.tree is None:
            return []
        definition = self.definition()
        imported_pytest_assertions = _imported_pytest_assertion_callees(unit.tree)
        findings: list[Finding] = []
        # Each collected test needs at least one construct that can fail on an unmet expectation.
        for fn, scope in test_functions(unit):
            # Fixtures and conftest helpers support tests but are not collected test cases here.
            if _is_no_assertions_support_function(fn, scope):
                continue
            # A recognised assertion makes the test verifiable, so no finding is needed.
            if _has_any_assertion(fn, imported_pytest_assertions):
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


def _has_any_assertion(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    imported_pytest_assertions: frozenset[str],
) -> bool:
    """Return whether a test contains a construct that verifies an expectation.

    Args:
        fn: Collected test function to inspect.
        imported_pytest_assertions: Callee names resolved from pytest imports; empty means the
            source uses no supported direct or aliased imports.

    Returns:
        True when the test contains an assertion statement or recognised assertion-like call.
    """
    # Test bodies may verify through statements, direct calls, or context managers.
    for node in walk_test_body(fn):
        # A Python assertion fails the test when its expectation is false.
        if isinstance(node, ast.Assert):
            return True
        # Standalone framework helpers can fail without a language-level assert statement.
        if isinstance(node, ast.Call) and _is_standalone_assertion_call(
            node, imported_pytest_assertions
        ):
            return True
        # Exception and warning expectations are expressed as context managers.
        if isinstance(node, ast.With) and _has_with_item_assertion(
            node, imported_pytest_assertions
        ):
            return True
    return _has_decorator_assertion_call(fn, imported_pytest_assertions)


def _is_standalone_assertion_call(
    call: ast.Call,
    imported_pytest_assertions: frozenset[str],
) -> bool:
    """Recognise direct verification calls while excluding bare warning-state isolation.

    Args:
        call: Call expression outside special ``with`` handling.
        imported_pytest_assertions: Callee names resolved from pytest imports; empty means only
            canonical and assertion-named calls can match.

    Returns:
        True when the call can directly fail the test on an unmet expectation.
    """
    return _is_recognised_assertion_call(
        call, imported_pytest_assertions
    ) and not is_catch_warnings_call(call)


def _has_with_item_assertion(
    with_statement: ast.With,
    imported_pytest_assertions: frozenset[str],
) -> bool:
    """Return whether a context manager verifies an exception or warning expectation.

    Args:
        with_statement: ``with`` statement whose context managers may assert behaviour.
        imported_pytest_assertions: Callee names resolved from pytest imports; empty means only
            canonical and assertion-named calls can match.

    Returns:
        True when any context manager can fail the test on an unmet expectation.
    """
    # Any assertion-like context manager is enough to make the test verifiable.
    for item in with_statement.items:
        # Ordinary resource managers do not verify an outcome.
        if not (
            isinstance(item.context_expr, ast.Call)
            and _is_recognised_assertion_call(item.context_expr, imported_pytest_assertions)
        ):
            continue
        # Catching warnings verifies behavior only when warnings are promoted to failures.
        if is_catch_warnings_call(item.context_expr):
            # An error filter turns any matching warning into a failed test.
            if has_error_warnings_filter(with_statement):
                return True
            continue
        return True
    return False


def _has_decorator_assertion_call(
    test_function: ast.FunctionDef | ast.AsyncFunctionDef,
    imported_pytest_assertions: frozenset[str],
) -> bool:
    """Return whether parametrization constructs an assertion context for the test.

    Args:
        test_function: Collected test whose decorators provide parameter values.
        imported_pytest_assertions: Callee names resolved from pytest imports; empty means only
            canonical and assertion-named calls can match.

    Returns:
        True when a decorator creates a recognised assertion helper.
    """
    # Parametrized tests may receive a pre-built raises or warns context from their decorator.
    for decorator in test_function.decorator_list:
        # Assertion helpers may be nested inside a list or tuple of parameter values.
        for node in ast.walk(decorator):
            # The decorator supplies a verification context even if the body only enters it.
            if isinstance(node, ast.Call) and _is_standalone_assertion_call(
                node, imported_pytest_assertions
            ):
                return True
    return False


def _is_recognised_assertion_call(
    call: ast.Call,
    imported_pytest_assertions: frozenset[str],
) -> bool:
    """Recognise canonical calls and names bound through pytest imports.

    Args:
        call: Call expression to classify.
        imported_pytest_assertions: Callee names resolved from pytest imports; empty means the
            source uses no supported direct or aliased imports.

    Returns:
        True when the shared matcher or an import-aware callee match recognises the call.
    """
    return is_assertion_call(call) or _callee_name(call) in imported_pytest_assertions


def _imported_pytest_assertion_callees(tree: ast.AST) -> frozenset[str]:
    """Resolve direct and module-aliased pytest assertion helper names in one source tree.

    Use this once per analysed file so every test in the file shares the same import lookup.

    Args:
        tree: Parsed Python source whose imports establish local pytest names.

    Returns:
        Callee names such as ``raises`` or ``pt.warns``; empty means no supported aliases exist.
    """
    assertion_callees: set[str] = set()
    # Imports are collected once per file rather than rediscovered for every test function.
    for node in ast.walk(tree):
        # A module alias applies to each assertion-like helper exposed by pytest.
        if isinstance(node, ast.Import):
            # One import statement may bind several unrelated modules.
            for imported_module in node.names:
                # Canonical ``pytest`` calls are already covered by the shared matcher.
                if imported_module.name != "pytest" or imported_module.asname is None:
                    continue
                assertion_callees.update(
                    f"{imported_module.asname}.{helper_name}"
                    for helper_name in _PYTEST_ASSERTION_HELPERS
                )
            continue
        # Direct imports bind one helper name, optionally under a local alias.
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            # Only helpers with assertion semantics can satisfy this rule.
            for imported_helper in node.names:
                if imported_helper.name not in _PYTEST_ASSERTION_HELPERS:
                    continue
                assertion_callees.add(imported_helper.asname or imported_helper.name)
    return frozenset(assertion_callees)


def _callee_name(call: ast.Call) -> str | None:
    """Return the simple or one-level dotted name used for an assertion call.

    Args:
        call: Call expression whose imported binding may identify an assertion helper.

    Returns:
        A name such as ``raises`` or ``pt.raises``; ``None`` means the callee has another shape.
    """
    # Direct imports produce a simple local name.
    if isinstance(call.func, ast.Name):
        return call.func.id
    # ``import pytest as pt`` produces a one-level dotted helper call.
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return f"{call.func.value.id}.{call.func.attr}"
    return None


def _is_no_assertions_support_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    scope: TestScope,
) -> bool:
    """Return whether a fixture or conftest helper is outside collected-test analysis."""
    # Conftest functions support collection and fixtures rather than acting as collected tests.
    if scope.kind is TestScopeKind.CONFTEST:
        return True
    # A fixture decorator keeps even a ``test_*``-named factory outside test collection.
    return any(is_pytest_fixture_decorator(decorator) for decorator in fn.decorator_list)
