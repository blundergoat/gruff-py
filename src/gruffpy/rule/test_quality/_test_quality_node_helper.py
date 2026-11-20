"""Shared scope detection and assertion recognition for the test-quality pillar.

Memoised per-tree so every test-quality rule shares a single AST walk per
analyse run, regardless of how many rules read it.

Public surface:

- :func:`scopes_for_unit` - returns a ``{FunctionDef: TestScope}`` mapping for
  every function in the unit's tree, classified into test / non-test scope.
- :func:`test_functions` - iterator over (function, scope) pairs where scope.kind
  is one of the test variants. Filters out non-test functions.
- :func:`is_assertion_call` - recognise ``self.assertEqual(...)``,
  ``assert_helper(...)``, ``pytest.raises``, and ``assert <expr>`` (handled
  separately at the rule level since ``assert`` is a statement, not a call).
- :func:`compute_count` - instrumentation counter (number of times the scope map
  was computed). The memoisation gate test reads this to confirm the helper
  memoises correctly.
"""

import ast
from collections.abc import Iterator
from weakref import WeakKeyDictionary

from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.test_quality._test_quality_scope import TestScope, TestScopeKind

ScopeMap = dict[ast.FunctionDef | ast.AsyncFunctionDef, TestScope]

_scope_cache: WeakKeyDictionary[ast.AST, ScopeMap] = WeakKeyDictionary()
_compute_counter = {"count": 0}


def scopes_for_unit(unit: AnalysisUnit) -> ScopeMap:
    """Return scope classifications for function declarations outside function bodies.

    Cache misses store a shared map and increment the computation counter; later calls return the same mutable map.
    Units without a tree return an empty map.

    Args:
        unit: Parsed analysis unit to classify.

    Returns:
        Mapping from function nodes to their test scope.
    """
    tree = unit.tree
    if tree is None:
        return {}
    cached = _scope_cache.get(tree)
    if cached is not None:
        return cached
    file_is_conftest = unit.file.display_path.endswith("conftest.py")
    computed = _compute_scopes(tree, file_is_conftest)
    _scope_cache[tree] = computed
    _compute_counter["count"] += 1
    return computed


def iter_test_functions(
    unit: AnalysisUnit,
) -> Iterator[tuple[ast.FunctionDef | ast.AsyncFunctionDef, TestScope]]:
    """Yield function/scope pairs for every function in test scope.

    On a cache miss for a parsed tree, iteration caches the scopes and increments the shared computation counter.

    Args:
        unit: Analysis unit whose tree supplies the function classifications.

    Yields:
        Function and test-related scope pairs, including conftest helpers. An unparsed unit or no matching scopes yields no pairs.
    """
    for fn, scope in scopes_for_unit(unit).items():
        if scope.kind is not TestScopeKind.NON_TEST:
            yield fn, scope


test_functions = iter_test_functions


def is_assertion_call(call: ast.Call) -> bool:
    """Return whether a call expression is an assertion helper.

    Args:
        call: Call whose callee spelling is checked against the assertion and helper names.

    Returns:
        True for recognized assertion-named calls, supported pytest helpers, or warnings.catch_warnings; false otherwise.
    """
    callee = call.func
    if isinstance(callee, ast.Name):
        return callee.id.startswith("assert_")
    if isinstance(callee, ast.Attribute):
        if _is_assertion_helper_name(callee.attr):
            return True
        if callee.attr in {
            "raises",
            "warns",
            "deprecated_call",
            "approx",
            "fail",
        } and _is_pytest_ref(callee.value):
            return True
        if callee.attr == "catch_warnings" and _dotted_name(callee.value) == "warnings":
            return True
    return False


def _is_assertion_helper_name(name: str) -> bool:
    """Recognize assertion-helper naming conventions.

    Args:
        name: Bare function or attribute spelling to test for an assertion prefix.

    Returns:
        True for an assert_ prefix or assert followed by an uppercase character; false otherwise.
    """
    if name.startswith("assert_"):
        return True
    return len(name) > len("assert") and name.startswith("assert") and name[6].isupper()


def is_catch_warnings_call(call: ast.Call) -> bool:
    """Recognize catch_warnings calls by their extracted receiver name.

    The no-assertions rule additionally requires an error filter; other rules use the broader assertion classification.

    Args:
        call: Call whose callee attribute and receiver name identify the warnings context helper.

    Returns:
        True for a catch_warnings attribute whose extracted receiver spelling is warnings; false otherwise.
    """
    callee = call.func
    return isinstance(callee, ast.Attribute) and callee.attr == "catch_warnings" and _dotted_name(callee.value) == "warnings"


def has_error_warnings_filter(node: ast.AST) -> bool:
    """Recognize warnings filter calls with the literal error string as their first positional argument.

    Args:
        node: Subtree searched for simplefilter or filterwarnings calls whose extracted receiver name is warnings.

    Returns:
        True when a matching call has the literal error action; false otherwise.
    """
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        callee = child.func
        if not (isinstance(callee, ast.Attribute) and callee.attr in {"simplefilter", "filterwarnings"} and _dotted_name(callee.value) == "warnings"):
            continue
        first_arg = child.args[0] if child.args else None
        if isinstance(first_arg, ast.Constant) and first_arg.value == "error":
            return True
    return False


def is_pytest_fixture_decorator(decorator: ast.AST) -> bool:
    """Recognize fixture decorator spellings without resolving their imports.

    Args:
        decorator: Decorator expression that supplies the name to match. A decorator call supplies its callee name.

    Returns:
        True when the extracted spelling is fixture or ends with .fixture; false for other or unknown spellings.
    """
    name = _dotted_name(decorator)
    if name is None:
        return False
    return name == "fixture" or name.endswith(".fixture")


def compute_count() -> int:
    """Return the number of complete scope-map computations since the last counter reset.

    Returns:
        Number of complete scope-map computations performed.
    """
    return _compute_counter["count"]


def reset_compute_count() -> None:
    """Reset the shared scope-computation counter for tests.

    Returns:
        None; the shared counter is set to zero.
    """
    _compute_counter["count"] = 0


# Dotted suffixes that identify a call as a mock factory.
_MOCK_FACTORY_LEAVES: frozenset[str] = frozenset(
    {
        "Mock",
        "MagicMock",
        "AsyncMock",
        "NonCallableMock",
        "NonCallableMagicMock",
        "PropertyMock",
        "create_autospec",
        "patch",
        "patch_object",
    }
)


def is_mock_factory_call(call: ast.Call) -> bool:
    """Recognize mock-factory call spellings for test-quality analysis.

    Matching uses names only; any dotted target with patch before its final component is also accepted.

    Args:
        call: Call whose callee spelling supplies the components for mock-factory matching.

    Returns:
        True for a supported factory leaf or a non-final patch component; false for other or unnamed targets.
    """
    target = _dotted_name(call.func)
    if target is None:
        return False
    leaf = target.split(".")[-1]
    if leaf in _MOCK_FACTORY_LEAVES:
        return True
    # A patch component can precede object or dict instead of being the target's final component.
    parts = target.split(".")
    return any(part == "patch" for part in parts[:-1])


def find_mock_bindings(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.AST]:
    """Return variable bindings created from mock factories.

    Recognizes simple assignments, annotated assignments, and with-statement aliases from supported mock factories.

    Args:
        fn: Test function whose body is scanned without entering nested functions or lambdas.

    Returns:
        Mapping of each name to its last matching assignment or with-item node in traversal order. Empty when no bindings match.
    """
    bindings: dict[str, ast.AST] = {}
    for node in walk_test_body(fn):
        bindings.update(_mock_bindings_for_node(node))
    return bindings


def _mock_bindings_for_node(node: ast.AST) -> dict[str, ast.AST]:
    """Extract simple-name bindings from supported mock-producing statements.

    Args:
        node: Assignment, annotated assignment or with statement to inspect for recognized mock factories.

    Returns:
        Names mapped to their original assignment or with-item nodes; an empty mapping for unsupported or unmatched syntax.
    """
    if isinstance(node, ast.Assign):
        return _assign_mock_bindings(node)
    if isinstance(node, ast.AnnAssign):
        return _ann_assign_mock_bindings(node)
    if isinstance(node, ast.With):
        return _with_mock_bindings(node)
    return {}


def _assign_mock_bindings(node: ast.Assign) -> dict[str, ast.AST]:
    """Extract simple targets of a recognized mock-factory assignment.

    Args:
        node: Assignment whose right-hand call and direct target names are inspected.

    Returns:
        Simple target names mapped to the supplied assignment node; an empty mapping when the value is not a recognized factory call
        or no target is a simple name.
    """
    if not isinstance(node.value, ast.Call) or not is_mock_factory_call(node.value):
        return {}
    return {target.id: node for target in node.targets if isinstance(target, ast.Name)}


def _ann_assign_mock_bindings(node: ast.AnnAssign) -> dict[str, ast.AST]:
    """Extract a simple annotated binding to the result of a recognized mock factory call.

    Args:
        node: Annotated assignment whose optional value and target are inspected.

    Returns:
        The name mapped to the supplied node, or an empty mapping unless the target is a name and the value is a recognized mock factory call.
    """
    if node.value is None or not isinstance(node.value, ast.Call) or not is_mock_factory_call(node.value) or not isinstance(node.target, ast.Name):
        return {}
    return {node.target.id: node}


def _with_mock_bindings(node: ast.With) -> dict[str, ast.AST]:
    """Extract simple with-aliases for recognized mock-factory contexts.

    Args:
        node: With statement whose context calls and optional aliases are inspected.

    Returns:
        Alias names mapped to their original with-item nodes; non-name aliases and unrecognized contexts are omitted.
    """
    bindings: dict[str, ast.AST] = {}
    for item in node.items:
        if isinstance(item.context_expr, ast.Call) and is_mock_factory_call(item.context_expr) and isinstance(item.optional_vars, ast.Name):
            bindings[item.optional_vars.id] = item
    return bindings


def walk_test_body(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.AST]:
    """Yield test-body nodes while leaving nested function and lambda nodes unexpanded.

    The walk also visits nested class bodies.

    Args:
        fn: Test function to walk.

    Yields:
        Each visited body node, including nested function and lambda nodes before their children are skipped.
    """

    def _visit(node: ast.AST) -> Iterator[ast.AST]:
        yield node
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            return
        for child in ast.iter_child_nodes(node):
            yield from _visit(child)

    for stmt in fn.body:
        yield from _visit(stmt)


def _compute_scopes(tree: ast.AST, file_is_conftest: bool) -> ScopeMap:
    """Build scope classifications without descending into function bodies.

    Args:
        tree: AST root to walk for function declarations and enclosing classes.
        file_is_conftest: Whether every encountered function receives the conftest classification.

    Returns:
        A new map keyed by encountered function nodes; functions nested inside function bodies are not visited.
    """
    scope_map: ScopeMap = {}
    _walk(tree, parent_class=None, file_is_conftest=file_is_conftest, scope_map=scope_map)
    return scope_map


def _walk(
    node: ast.AST,
    parent_class: ast.ClassDef | None,
    file_is_conftest: bool,
    scope_map: ScopeMap,
) -> None:
    """Populate function-scope classifications while stopping at each function body.

    Args:
        node: Current AST node whose declaration or children are inspected.
        parent_class: Active enclosing class, or None when no class has been entered.
        file_is_conftest: Whether conftest classification overrides function and class naming conventions.
        scope_map: Caller-owned mapping populated with encountered function nodes and their classifications.

    Returns:
        None; discovered classifications are written into scope_map.
    """
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        scope = _classify_function(node, parent_class, file_is_conftest)
        scope_map[node] = scope
        return
    if isinstance(node, ast.ClassDef):
        for child in ast.iter_child_nodes(node):
            _walk(child, parent_class=node, file_is_conftest=file_is_conftest, scope_map=scope_map)
        return
    for child in ast.iter_child_nodes(node):
        _walk(
            child,
            parent_class=parent_class,
            file_is_conftest=file_is_conftest,
            scope_map=scope_map,
        )


def _classify_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_class: ast.ClassDef | None,
    file_is_conftest: bool,
) -> TestScope:
    """Choose a function's test scope from file and enclosing-class context.

    Args:
        fn: Function declaration whose name and async form are inspected.
        parent_class: Enclosing class to classify by its base/name spellings, or None for a bare function.
        file_is_conftest: Whether the conftest classification takes precedence over all naming checks.

    Returns:
        The selected test or non-test classification, with async status and the applicable enclosing class name.
    """
    is_async = isinstance(fn, ast.AsyncFunctionDef)
    if file_is_conftest:
        return TestScope(kind=TestScopeKind.CONFTEST, is_async=is_async, parent_class_name=None)
    if parent_class is None:
        return _bare_function_scope(fn, is_async)
    parent_name = parent_class.name
    if _is_unittest_testcase(parent_class):
        return _class_method_scope(
            is_test=fn.name.startswith("test"),
            test_kind=TestScopeKind.UNITTEST_TEST_METHOD,
            is_async=is_async,
            parent_name=parent_name,
        )
    if parent_name.startswith("Test"):
        return _class_method_scope(
            is_test=fn.name.startswith("test_"),
            test_kind=TestScopeKind.PYTEST_TEST_METHOD,
            is_async=is_async,
            parent_name=parent_name,
        )
    return TestScope(kind=TestScopeKind.NON_TEST, is_async=is_async, parent_class_name=parent_name)


def _bare_function_scope(fn: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> TestScope:
    """Classify a function outside class scope by its name.

    Args:
        fn: Function declaration checked for the test_ prefix.
        is_async: Async status already determined by the caller and retained in the result.

    Returns:
        A bare-test classification for a test_ name, otherwise non-test, without an enclosing class name.
    """
    kind = TestScopeKind.BARE_TEST_FUNC if fn.name.startswith("test_") else TestScopeKind.NON_TEST
    return TestScope(kind=kind, is_async=is_async)


def _class_method_scope(
    *,
    is_test: bool,
    test_kind: TestScopeKind,
    is_async: bool,
    parent_name: str,
) -> TestScope:
    """Build the classification for a method in a recognized test class.

    Args:
        is_test: Whether the method name meets the enclosing test class's convention.
        test_kind: Test classification to retain when is_test is true.
        is_async: Async status to retain in the resulting scope.
        parent_name: Enclosing class name to retain for both test and non-test methods.

    Returns:
        A scope carrying test_kind when is_test is true, otherwise non-test, with the supplied async and class context.
    """
    return TestScope(
        kind=test_kind if is_test else TestScopeKind.NON_TEST,
        is_async=is_async,
        parent_class_name=parent_name,
    )


def _is_unittest_testcase(cls: ast.ClassDef) -> bool:
    """Recognize unittest-style classes by their base expression spellings.

    The cls argument supplies the class node whose base-expression spellings are inspected; no base class is imported.

    Returns:
        True for bare or qualified TestCase and IsolatedAsyncioTestCase spellings; false when no base matches.
    """
    for base in cls.bases:
        name = _dotted_name(base)
        if name is None:
            continue
        if name in {"TestCase", "unittest.TestCase", "IsolatedAsyncioTestCase"}:
            return True
        if name.endswith((".TestCase", ".IsolatedAsyncioTestCase")):
            return True
    return False


def _dotted_name(node: ast.AST) -> str | None:
    """Extract an available name spelling, unwrapping call expressions.

    Args:
        node: Expression whose callee, name or attribute chain is inspected without resolving imports.

    Returns:
        The dotted spelling, an attribute suffix when its receiver is unrecognized, or None for unsupported syntax.
    """
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        if prefix is None:
            return node.attr
        return f"{prefix}.{node.attr}"
    return None


def _is_pytest_ref(node: ast.AST) -> bool:
    """Check whether an expression's extracted spelling is exactly pytest.

    Args:
        node: Receiver expression to inspect using the same name extraction as assertion recognition.

    Returns:
        True when the extracted spelling is pytest; false for other or unrecognized spellings.
    """
    name = _dotted_name(node)
    return name == "pytest"
