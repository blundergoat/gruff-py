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
        """Check runner eligibility before assertion analysis screens support functions.

        Args:
            scope_kind: Candidate classification used to decide whether unittest discovery applies.

        Returns:
            True if the file matches pytest collection, or if it matches unittest discovery and the scope is a TestCase test method.
        """
        # Only TestCase test methods can qualify through unittest discovery. Other candidate scopes need a pytest match.
        if scope_kind is TestScopeKind.UNITTEST_TEST_METHOD:
            return self.by_pytest or self.by_unittest
        return self.by_pytest


class NoAssertionsRule(Rule):
    """Detect test functions containing zero assertion statements or helper calls."""

    ID = "test-quality.no-assertions"

    def definition(self) -> RuleDefinition:
        """Describe the no-assertions rule as a high-confidence warning.

        Such tests provide no recognized syntactic evidence of an expected outcome.

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
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag eligible tests with no recognized assertion-like syntax.

        Recognition includes nested bodies, patch replacements referencing raising fakes, and decorator calls; support functions are excluded.

        Args:
            unit: Parsed source file to inspect; a missing AST yields no findings.
            context: Rule execution context supplying the project root for pytest discovery settings cached on first lookup.

        Returns:
            One finding per eligible test with no recognized assertion-like syntax.
        """
        # Without an AST, an empty result means the file was never checked for assertions.
        if unit.tree is None:
            return []
        collection = _collection_for_unit(unit, context)
        # Keep test-like helpers out of the report when neither runner's discovery convention admits their file.
        if not (collection.by_pytest or collection.by_unittest):
            return []
        definition = self.definition()
        imported_pytest_assertions = _imported_pytest_assertion_callees(unit.tree)
        task_runner_decorators = _imported_task_runner_decorators(unit.tree)
        findings: list[Finding] = []
        for fn, scope in test_functions(unit):
            if not collection.is_collected(scope.kind):
                continue
            # Fixtures, conftest helpers, and task-runner sessions support tests but are not test cases.
            if _is_no_assertions_support_function(fn, scope, task_runner_decorators):
                continue
            # Recognized assertion syntax satisfies this rule even when its execution cannot be established.
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
    """Detect assertion-like syntax accepted by the no-assertions rule.

    Args:
        fn: Collected test function to inspect.
        imported_pytest_assertions: Additional pytest callee spellings from imports; empty adds no matches beyond built-in name checks.

    Returns:
        True for recognized body syntax, an accepted patch replacement, or a recognized decorator call; false otherwise.
    """
    # Nested helpers and callbacks count syntactically even when this walk cannot show that the test invokes them.
    for node in _walk_test_body_deeply(fn):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call) and _is_standalone_assertion_call(node, imported_pytest_assertions):
            return True
        if isinstance(node, ast.With) and _has_with_item_assertion(node, imported_pytest_assertions):
            return True
    return _has_installed_failure_fake(fn) or _has_decorator_assertion_call(fn, imported_pytest_assertions)


def _has_installed_failure_fake(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Recognise a local raising fake supplied as a patch replacement.

    A matching fake must occupy a replacement position or a new or side_effect keyword; target-only references do not count.

    Args:
        fn: Test function whose nested fakes and patch calls are inspected.

    Returns:
        True when a recognized patch call names a local fake containing an AssertionError raise; false otherwise.
    """
    failures = {
        node.name
        for node in ast.walk(fn)
        if node is not fn
        and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and any(_is_assertion_failure(value) for statement in node.body for value in ast.walk(statement))
    }
    for call in _walk_test_body_deeply(fn):
        if not isinstance(call, ast.Call) or _callee_name(call) not in {
            "monkeypatch.setattr",
            "patch",
            "patch.object",
            "mock.patch",
            "mock.patch.object",
            "unittest.mock.patch",
            "unittest.mock.patch.object",
        }:
            continue
        target = _callee_name(call) or ""
        position = 2 if target.endswith(".object") or (target.endswith(".setattr") and len(call.args) >= 3) else 1
        replacements = [call.args[position]] if len(call.args) > position else []
        replacements.extend(keyword.value for keyword in call.keywords if keyword.arg in {"new", "side_effect"})
        if any(isinstance(value, ast.Name) and value.id in failures for value in replacements):
            return True
    return False


def _is_assertion_failure(node: ast.AST) -> bool:
    """Recognize a raise of the bare AssertionError name or its constructor.

    Args:
        node: AST node inspected for an explicit AssertionError raise.

    Returns:
        True for raise AssertionError or raise AssertionError(...); false for bare re-raises and other exception spellings.
    """
    if not isinstance(node, ast.Raise) or node.exc is None:
        return False
    exception = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    return isinstance(exception, ast.Name) and exception.id == "AssertionError"


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
    """Detect recognized assertion-like with-items, with special handling for warning filters.

    Args:
        with_statement: With statement whose context calls are classified by their extracted spellings.
        imported_pytest_assertions: Additional pytest callee spellings from imports; empty leaves only built-in name checks.

    Returns:
        True for a recognized context call; catch_warnings additionally needs an error filter. False otherwise.
    """
    # Warning-state isolation alone does not satisfy this rule.
    for item in with_statement.items:
        if not (isinstance(item.context_expr, ast.Call) and _is_recognised_assertion_call(item.context_expr, imported_pytest_assertions)):
            continue
        # A recognized catch_warnings call counts only with a literal error filter somewhere in the with subtree.
        if is_catch_warnings_call(item.context_expr):
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
        call: Expression whose callee is checked for a recognized assertion spelling.
        imported_pytest_assertions: Extra callee spellings from imports. An empty set leaves the shared and private-name checks in effect.

    Returns:
        True for a shared assertion match, a bare name or one-level attribute starting with _assert at its leaf, or a collected pytest name.
    """
    target = _callee_name(call)
    private_assertion = target is not None and target.split(".")[-1].startswith("_assert")
    return is_assertion_call(call) or private_assertion or target in imported_pytest_assertions


def _imported_pytest_assertion_callees(tree: ast.AST) -> frozenset[str]:
    """Collect extra pytest assertion spellings by matching import syntax across one source tree.

    Use this once per analysed file so every test in the file shares the same import lookup.

    Args:
        tree: Parsed Python source whose imports establish local pytest names.

    Returns:
        Helper spellings from pytest module aliases and from-imports whose module field is pytest. Empty means no extra spellings were found.
    """
    assertion_callees: set[str] = set()
    for node in ast.walk(tree):
        # A module alias gives the rule another spelling for each supported helper.
        if isinstance(node, ast.Import):
            for imported_module in node.names:
                # Canonical pytest calls are already covered by the shared matcher.
                if imported_module.name != "pytest" or imported_module.asname is None:
                    continue
                assertion_callees.update(f"{imported_module.asname}.{helper_name}" for helper_name in _PYTEST_ASSERTION_HELPERS)
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            # Direct imports use the same helper allowlist as module aliases.
            for imported_helper in node.names:
                if imported_helper.name not in _PYTEST_ASSERTION_HELPERS:
                    continue
                assertion_callees.add(imported_helper.asname or imported_helper.name)
    return frozenset(assertion_callees)


def _callee_name(call: ast.Call) -> str | None:
    """Return the bare or one-level dotted spelling of a call target.

    Args:
        call: Call expression whose callee spelling is inspected without resolving imports.

    Returns:
        Callee spelling, or None unless the callee is a name or an attribute on a name.
    """
    # Direct imports produce a simple local name.
    if isinstance(call.func, ast.Name):
        return call.func.id
    # An aliased module import can make an assertion helper use a dotted spelling.
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        return f"{call.func.value.id}.{call.func.attr}"
    return None


def _walk_test_body_deeply(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Yield every node beneath a test's body statements for assertion detection.

    Nested helpers and callbacks are included because this rule counts assertion syntax within those scopes.

    Args:
        fn: Collected test function to walk.

    Yields:
        AST nodes in the body subtree, including nested decorators and defaults; excludes the outer function's decorators and defaults.
    """
    # The outer function's decorators and defaults execute at definition time, so assertion detection starts at its body.
    for statement in fn.body:
        yield from ast.walk(statement)


def _collection_for_unit(unit: AnalysisUnit, context: RuleContext) -> _Collection:
    """Estimate file eligibility from discovery names and the package-location heuristic.

    Args:
        unit: Parsed source file whose path is matched against collection conventions.
        context: Rule execution context whose project root locates pyproject.toml and keys the shared config cache populated on first lookup.

    Returns:
        Runner-convention flags. Both false exclude the file from this rule. Missing or empty python_files settings use the default pytest globs.
    """
    display_path = unit.file.display_path.replace("\\", "/")
    basename = PurePosixPath(display_path).name
    patterns = read_pytest_config(context.project_root).python_files or _DEFAULT_PYTHON_FILES
    by_pytest = any(_matches_python_files(display_path, basename, pattern) for pattern in patterns)
    by_unittest = fnmatch.fnmatchcase(basename, _UNITTEST_DISCOVERY_PATTERN)
    # The package-location heuristic excludes likely library helpers even when their names match test globs.
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
    """Identify regular-package paths outside test directories for exclusion from collected-test analysis.

    Args:
        absolute_path: Filesystem path used to look for ``__init__.py`` in each parent directory.
        display_path: Project-relative path whose directory segments are inspected.

    Returns:
        True when every directory between the project root and file has an __init__.py and none is a test directory;
        false for root-level files and outside-project paths.
    """
    directories = PurePosixPath(display_path).parent.parts
    # Root-level, outside-project and test-directory paths do not qualify for this package-based exclusion.
    if not directories or directories[0] in {"/", ".."} or any(part in _TEST_DIRECTORY_NAMES for part in directories):
        return False
    package_directory = Path(absolute_path).parent
    for _segment in directories:
        # Importable namespace packages are not sufficient evidence for this regular-package exclusion.
        if not (package_directory / "__init__.py").is_file():
            return False
        package_directory = package_directory.parent
    return True


def _imported_task_runner_decorators(tree: ast.AST) -> frozenset[str]:
    """Return canonical task-runner decorator spellings plus names found in imports.

    Args:
        tree: Parsed Python source inspected for imports of nox.session or invoke.task.

    Returns:
        Canonical nox.session and invoke.task spellings plus supported import names; canonical names remain when no imports match.
    """
    decorator_names = {f"{module}.{decorator}" for module, decorator in _TASK_RUNNER_DECORATORS.items()}
    # Imports are collected once per file rather than rediscovered for every candidate function.
    for node in ast.walk(tree):
        # Importing nox as n gives the decorator spelling n.session.
        if isinstance(node, ast.Import):
            decorator_names.update(
                f"{alias.asname}.{_TASK_RUNNER_DECORATORS[alias.name]}"
                for alias in node.names
                if alias.name in _TASK_RUNNER_DECORATORS and alias.asname is not None
            )
            continue
        # A direct import can expose the decorator without the task-runner module prefix.
        if isinstance(node, ast.ImportFrom) and node.module in _TASK_RUNNER_DECORATORS:
            decorator_names.update(alias.asname or alias.name for alias in node.names if alias.name == _TASK_RUNNER_DECORATORS[node.module])
    return frozenset(decorator_names)


def _is_no_assertions_support_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    scope: TestScope,
    task_runner_decorators: frozenset[str],
) -> bool:
    """Identify candidate functions to skip when checking for missing assertions.

    Args:
        fn: Candidate whose decorators are checked for an exemption.
        scope: Classification used to exempt conftest functions.
        task_runner_decorators: Accepted spellings for nox.session and invoke.task, including recognized import aliases.

    Returns:
        True for conftest functions or candidates with a recognized fixture or task-runner decorator.
    """
    # Treat conftest functions as support code even when their names resemble test cases.
    if scope.kind is TestScopeKind.CONFTEST:
        return True
    # A recognized decorator exempts even a function whose name begins with test_.
    return any(is_pytest_fixture_decorator(decorator) or _decorator_name(decorator) in task_runner_decorators for decorator in fn.decorator_list)
