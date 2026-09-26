"""``test-quality.no-assertions`` - test function with zero assertion-like calls.

Looks for ``assert`` statements, ``self.assertEqual`` / ``self.assertX`` calls,
``assert_*`` helper calls, and ``pytest.raises`` / ``pytest.warns`` contexts,
including direct and aliased imports and those inside nested helpers or
callbacks. A test with none of these is probably testing nothing.

Only tests a runner would collect are judged: the file must match pytest's
``python_files`` globs (unittest's ``test*.py`` also admits ``TestCase``
methods), it must not be importable package code outside a test directory, and
the function must not be a fixture, a nox session, or an invoke task.
"""

import ast
import fnmatch
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import _decorator_name
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._pytest_config import read_pytest_config
from gruffpy.rule.test_quality._test_quality_node_helper import (
    has_error_warnings_filter,
    is_assertion_call,
    is_catch_warnings_call,
    is_pytest_fixture_decorator,
    test_functions,
)
from gruffpy.rule.test_quality._test_quality_scope import TestScope, TestScopeKind

_PYTEST_ASSERTION_HELPERS: frozenset[str] = frozenset({"raises", "warns", "deprecated_call", "approx", "fail"})
# Pytest collects these files unless the project configures its own ``python_files`` globs.
_DEFAULT_PYTHON_FILES: tuple[str, ...] = ("test_*.py", "*_test.py")
# unittest discovery, which Django's runner shares, collects ``TestCase`` methods from these files.
_UNITTEST_DISCOVERY_PATTERN = "test*.py"
# A directory with one of these names holds tests even when it sits inside an importable package.
_TEST_DIRECTORY_NAMES: frozenset[str] = frozenset({"test", "tests", "testing"})
# A task runner, not a test runner, calls a function carrying one of these decorators.
_TASK_RUNNER_DECORATORS: dict[str, str] = {"nox": "session", "invoke": "task"}


@dataclass(frozen=True, slots=True)
class _Collection:
    """Which test runners would collect tests from one analysed file.

    Attributes:
        by_pytest: Whether the file matches pytest's collection globs and is not shipped package code.
        by_unittest: Whether unittest discovery would load the file's ``TestCase`` classes.
    """

    by_pytest: bool
    by_unittest: bool

    def is_collected(self, scope_kind: TestScopeKind) -> bool:
        """Return whether a function of this scope kind is a collected test in this file.

        Args:
            scope_kind: Test-scope classification of the function.

        Returns:
            True when some runner collects that kind of test from this file.
        """
        # unittest discovery loads only TestCase methods; bare functions and Test* classes are pytest's alone.
        if scope_kind is TestScopeKind.UNITTEST_TEST_METHOD:
            return self.by_pytest or self.by_unittest
        return self.by_pytest


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
        body, including inside nested helpers and callbacks it defines: a bare
        ``assert`` statement, a framework assertion call, an ``assert_*`` helper
        call, or a ``with`` item whose context manager is an assertion call
        (``warnings.catch_warnings`` only when the block escalates warnings to
        errors). Files no runner collects, shipped package modules, pytest
        fixtures, conftest support functions, nox sessions, and invoke tasks are
        not collected tests for this rule.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context; supplies the project root whose pytest settings name test files.

        Returns:
            One finding per collected test function with zero detected assertions.
        """
        # Sources without an AST cannot contain a collected Python test.
        if unit.tree is None:
            return []
        collection = _collection_for_unit(unit, context)
        # A file no runner collects holds no tests to verify, whatever its functions are named.
        if not (collection.by_pytest or collection.by_unittest):
            return []
        definition = self.definition()
        imported_pytest_assertions = _imported_pytest_assertion_callees(unit.tree)
        task_runner_decorators = _imported_task_runner_decorators(unit.tree)
        findings: list[Finding] = []
        # Each collected test needs at least one construct that can fail on an unmet expectation.
        for fn, scope in test_functions(unit):
            # A runner that does not load this kind of test from this file never executes it as one.
            if not collection.is_collected(scope.kind):
                continue
            # Fixtures, conftest helpers, and task-runner sessions support tests but are not test cases.
            if _is_no_assertions_support_function(fn, scope, task_runner_decorators):
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
                    remediation=("Assert the expected behaviour, raise on the unexpected, or delete the test if it's not exercising anything."),
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
    # Test bodies may verify through statements, direct calls, or context managers, in any scope they define.
    for node in _walk_test_body_deeply(fn):
        # A Python assertion fails the test when its expectation is false.
        if isinstance(node, ast.Assert):
            return True
        # Standalone framework helpers can fail without a language-level assert statement.
        if isinstance(node, ast.Call) and _is_standalone_assertion_call(node, imported_pytest_assertions):
            return True
        # Exception and warning expectations are expressed as context managers.
        if isinstance(node, ast.With) and _has_with_item_assertion(node, imported_pytest_assertions):
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
    return _is_recognised_assertion_call(call, imported_pytest_assertions) and not is_catch_warnings_call(call)


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
        if not (isinstance(item.context_expr, ast.Call) and _is_recognised_assertion_call(item.context_expr, imported_pytest_assertions)):
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
            if isinstance(node, ast.Call) and _is_standalone_assertion_call(node, imported_pytest_assertions):
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
                assertion_callees.update(f"{imported_module.asname}.{helper_name}" for helper_name in _PYTEST_ASSERTION_HELPERS)
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


def _walk_test_body_deeply(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Yield every node in a test body, including nested function and lambda bodies.

    The shared ``walk_test_body`` stops at nested scopes because most test-quality rules judge only a
    test's own statements. An assertion inside a callback or local helper the test registers still
    verifies the test, so this rule looks through those scopes.

    Args:
        fn: Collected test function to walk.

    Returns:
        Iterator over every node beneath the test's body statements; decorators and defaults are excluded.
    """
    # Decorators and argument defaults are not part of what the test executes, so only body statements are walked.
    for statement in fn.body:
        yield from ast.walk(statement)


def _collection_for_unit(unit: AnalysisUnit, context: RuleContext) -> _Collection:
    """Decide which test runners would collect tests from the analysed file.

    Args:
        unit: Parsed source file whose path is matched against collection conventions.
        context: Rule execution context; its project root locates ``pyproject.toml``.

    Returns:
        Collection flags; both false mean no runner loads tests from the file.
    """
    display_path = unit.file.display_path.replace("\\", "/")
    basename = PurePosixPath(display_path).name
    patterns = read_pytest_config(context.project_root).python_files or _DEFAULT_PYTHON_FILES
    by_pytest = any(_matches_python_files(display_path, basename, pattern) for pattern in patterns)
    by_unittest = fnmatch.fnmatchcase(basename, _UNITTEST_DISCOVERY_PATTERN)
    # Importable package code named like a test is shipped with the distribution rather than collected.
    if (by_pytest or by_unittest) and _is_shipped_package_module(unit.file.absolute_path, display_path):
        return _Collection(by_pytest=False, by_unittest=False)
    return _Collection(by_pytest=by_pytest, by_unittest=by_unittest)


def _matches_python_files(display_path: str, basename: str, pattern: str) -> bool:
    """Match one ``python_files`` glob the way pytest does.

    Args:
        display_path: Project-relative path of the analysed file, with forward slashes.
        basename: Final path segment of ``display_path``.
        pattern: Configured or default ``python_files`` glob.

    Returns:
        True when pytest would consider the file a test module under this glob.
    """
    # Pytest matches a glob carrying a path separator against the path, and any other glob against the basename.
    if "/" in pattern:
        return fnmatch.fnmatchcase(f"/{display_path}", f"*/{pattern.lstrip('/')}")
    return fnmatch.fnmatchcase(basename, pattern)


def _is_shipped_package_module(absolute_path: str, display_path: str) -> bool:
    """Return whether a file is importable package code outside any test directory.

    ``bandit/core/test_properties.py`` matches ``test_*.py``, yet ``bandit`` and ``bandit/core`` both carry
    ``__init__.py`` and no directory on the way is a test directory, so it ships with the distribution and
    its ``test_*`` decorator factories are not tests.

    Args:
        absolute_path: Filesystem path used to look for ``__init__.py`` in each parent directory.
        display_path: Project-relative path whose directory segments are inspected.

    Returns:
        True only when every directory between the project root and the file is a package and none is a
        test directory; a root-level file or a path outside the project is never shipped package code.
    """
    directories = PurePosixPath(display_path).parent.parts
    # Root-level files, paths outside the project, and test directories are where runners look for tests.
    if not directories or directories[0] in {"/", ".."} or any(part in _TEST_DIRECTORY_NAMES for part in directories):
        return False
    package_directory = Path(absolute_path).parent
    # Each directory up to the project root must be a package for the module to be importable from it.
    for _segment in directories:
        # A directory without ``__init__.py`` breaks the import path, so the file is not shipped package code.
        if not (package_directory / "__init__.py").is_file():
            return False
        package_directory = package_directory.parent
    return True


def _imported_task_runner_decorators(tree: ast.AST) -> frozenset[str]:
    """Resolve the local names under which the file imports a task-runner decorator.

    Args:
        tree: Parsed Python source whose imports bind ``nox.session`` or ``invoke.task``.

    Returns:
        Dotted decorator spellings such as ``nox.session``, ``session``, or ``n.session``.
    """
    decorator_names = {f"{module}.{decorator}" for module, decorator in _TASK_RUNNER_DECORATORS.items()}
    # Imports are collected once per file rather than rediscovered for every candidate function.
    for node in ast.walk(tree):
        # ``import nox as n`` makes ``@n.session`` the session decorator.
        if isinstance(node, ast.Import):
            decorator_names.update(
                f"{alias.asname}.{_TASK_RUNNER_DECORATORS[alias.name]}"
                for alias in node.names
                if alias.name in _TASK_RUNNER_DECORATORS and alias.asname is not None
            )
            continue
        # ``from nox import session`` binds the decorator itself, optionally under an alias.
        if isinstance(node, ast.ImportFrom) and node.module in _TASK_RUNNER_DECORATORS:
            decorator_names.update(alias.asname or alias.name for alias in node.names if alias.name == _TASK_RUNNER_DECORATORS[node.module])
    return frozenset(decorator_names)


def _is_no_assertions_support_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    scope: TestScope,
    task_runner_decorators: frozenset[str],
) -> bool:
    """Return whether a fixture, conftest helper, or task-runner session is outside collected-test analysis.

    Args:
        fn: Candidate test function.
        scope: Test-scope classification of the function.
        task_runner_decorators: Decorator spellings that bind ``nox.session`` or ``invoke.task`` in this file.

    Returns:
        True when the function supports tests or a task runner rather than being a collected test.
    """
    # Conftest functions support collection and fixtures rather than acting as collected tests.
    if scope.kind is TestScopeKind.CONFTEST:
        return True
    # A fixture, nox session, or invoke task keeps even a ``test_*``-named function outside test collection.
    return any(is_pytest_fixture_decorator(decorator) or _decorator_name(decorator) in task_runner_decorators for decorator in fn.decorator_list)
