"""Shared false-positive guards for test control-flow rules."""

import ast

_FIXTURE_NAME_MARKERS: tuple[str, ...] = (
    "case",
    "cases",
    "file",
    "files",
    "fixture",
    "fixtures",
    "path",
    "paths",
    "sample",
    "samples",
    "scenario",
    "scenarios",
)
_GUARD_SKIP_CALLS: frozenset[str] = frozenset({"pytest.skip", "skip", "self.skipTest", "unittest.skip"})


def is_fixture_loop(
    node: ast.For | ast.AsyncFor | ast.While,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return whether *node* is a bounded fixture/table sweep.

    Args:
        node: Loop statement found inside a test function.
        fn: Owning test function, used to discover local/module fixture tables.

    Returns:
        True when the loop is data-driven fixture coverage rather than
        assertion-hiding control flow.
    """
    if isinstance(node, ast.While):
        return False
    if _contains_branch(node.body):
        return False
    if not _is_fixture_iterable(node.iter, _literal_collection_bindings(fn), _target_names(node.target)):
        return False
    assertions = _assertions_in(node.body)
    return not assertions or all(assertion.msg is not None for assertion in assertions)


def is_subtest_loop(
    node: ast.For | ast.AsyncFor | ast.While,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Recognise a loop whose entire body carries unittest case context.

    Args:
        node: Candidate loop in a unittest test method.
        fn: Owning method, whose first argument binds the TestCase receiver.

    Returns:
        True when each statement is inside a subTest naming a bound loop value.
    """
    if isinstance(node, ast.While) or node.orelse or _contains_branch(node.body):
        return False
    parameters = [*fn.args.posonlyargs, *fn.args.args]
    if not parameters:
        return False
    receiver = parameters[0].arg
    if any(isinstance(n, ast.Name) and n.id == receiver and isinstance(n.ctx, ast.Store) for n in ast.walk(fn)):
        return False
    bound_names = _target_names(node.target)
    return bool(node.body) and all(_is_subtest_statement(statement, receiver, bound_names) for statement in node.body)


def _is_subtest_statement(statement: ast.stmt, receiver: str, bound_names: frozenset[str]) -> bool:
    """Recognize a with statement whose subTest arguments refer to a loop target.

    Args:
        statement: Loop-body statement to inspect for a matching with context.
        receiver: Name of the owning unittest method's TestCase receiver.
        bound_names: Loop-target names whose references establish case context.

    Returns:
        True when a matching subTest context argument contains a bound name; false otherwise.
    """
    if not isinstance(statement, ast.With):
        return False
    for item in statement.items:
        call = item.context_expr
        if not isinstance(call, ast.Call) or _call_name(call) != f"{receiver}.subTest":
            continue
        values = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(isinstance(n, ast.Name) and n.id in bound_names for value in values for n in ast.walk(value)):
            return True
    return False


def is_guard_clause(node: ast.If | ast.Match) -> bool:
    """Return whether a branch exits/skips rather than changing expectations.

    Args:
        node: Conditional node found inside a test function.

    Returns:
        True for simple ``if`` guards whose body only returns, raises, breaks,
        continues, or calls a recognised skip helper.
    """
    if isinstance(node, ast.Match) or node.orelse:
        return False
    return bool(node.body) and all(_is_guard_statement(statement) for statement in node.body)


def _literal_collection_bindings(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Collect fixture-named literal assignments from the function and outermost AST bodies.

    Args:
        fn: Owning function whose direct statements and parent-linked outermost body are inspected.

    Returns:
        Names assigned literal collections in either direct body; nested statement bodies are not searched.
    """
    bindings: set[str] = set()
    for scope in (_module_root(fn), fn):
        for statement in getattr(scope, "body", []):
            bindings.update(_literal_collection_targets(statement))
    return frozenset(bindings)


def _literal_collection_targets(statement: ast.stmt) -> set[str]:
    """Find fixture-named simple targets assigned a literal collection.

    Args:
        statement: Direct assignment or annotated assignment to inspect.

    Returns:
        Qualifying target names, or an empty set for other statements, values or target shapes.
    """
    if isinstance(statement, ast.Assign) and _is_literal_collection(statement.value):
        return {target.id for target in statement.targets if isinstance(target, ast.Name) and _is_fixtureish_name(target.id)}
    if (
        isinstance(statement, ast.AnnAssign)
        and statement.value is not None
        and isinstance(statement.target, ast.Name)
        and _is_fixtureish_name(statement.target.id)
        and _is_literal_collection(statement.value)
    ):
        return {statement.target.id}
    return set()


def _module_root(node: ast.AST) -> ast.AST:
    """Follow parent links to the outermost reachable AST node.

    Args:
        node: Starting node whose parser-provided parent links are followed.

    Returns:
        The topmost reachable ancestor, or node itself when it has no parent link.
    """
    current = node
    while hasattr(current, "parent"):
        current = current.parent
    return current


def _target_names(target: ast.expr) -> frozenset[str]:
    """Extract names directly bound by a loop target.

    Args:
        target: Loop target, either a simple name or a tuple/list of target expressions.

    Returns:
        The simple name or direct named elements of a tuple/list; nested unpacking and other shapes contribute no names.
    """
    if isinstance(target, ast.Name):
        return frozenset({target.id})
    if isinstance(target, ast.Tuple | ast.List):
        return frozenset(elt.id for elt in target.elts if isinstance(elt, ast.Name))
    return frozenset()


def _is_fixture_iterable(
    expr: ast.expr,
    bindings: frozenset[str],
    target_names: frozenset[str],
) -> bool:
    """Recognize iterable shapes accepted by the fixture-loop exemption.

    Args:
        expr: Loop iterable or wrapped first argument whose syntax is inspected.
        bindings: Names already recognized as fixture-named literal collection bindings.
        target_names: Loop-target names used to identify fixture-oriented literal collections.

    Returns:
        True for a qualifying literal, known binding or recognized fixture-call shape; false otherwise.
    """
    if _is_literal_collection(expr):
        return any(_is_fixtureish_name(name) for name in target_names)
    if isinstance(expr, ast.Name):
        return expr.id in bindings
    if isinstance(expr, ast.Call):
        return _is_fixture_call(expr, bindings, target_names)
    return False


def _is_fixture_call(
    call: ast.Call,
    bindings: frozenset[str],
    target_names: frozenset[str],
) -> bool:
    """Recognize fixture-enumeration call spellings and supported collection wrappers.

    Args:
        call: Call expression to inspect without resolving or executing its target.
        bindings: Known literal collection names used when inspecting a wrapper's first argument.
        target_names: Loop-target names used when the wrapped iterable is a literal collection.

    Returns:
        True for recognized glob/iterdir spellings or a supported wrapper around a fixture iterable; false otherwise.
    """
    name = _call_name(call)
    if name in {"glob", "Path.glob", "Path.rglob", "Path.iterdir"}:
        return True
    if name in {"list", "set", "sorted", "tuple"} and call.args:
        first = call.args[0]
        return isinstance(first, ast.expr) and _is_fixture_iterable(first, bindings, target_names)
    return name.endswith((".glob", ".rglob", ".iterdir"))


def _is_literal_collection(expr: ast.AST) -> bool:
    """Recognize collection literals used as fixture data.

    Args:
        expr: AST node to classify by its literal container shape.

    Returns:
        True for list, tuple, set or dict literals; false for other syntax, including comprehensions.
    """
    return isinstance(expr, ast.List | ast.Tuple | ast.Set | ast.Dict)


def _is_fixtureish_name(name: str) -> bool:
    """Check a name for a configured fixture-data marker.

    Args:
        name: Identifier spelling to search case-insensitively for fixture-related substrings.

    Returns:
        True when any fixture marker occurs in the name; false otherwise.
    """
    lowered = name.lower()
    return any(marker in lowered for marker in _FIXTURE_NAME_MARKERS)


def _contains_branch(statements: list[ast.stmt]) -> bool:
    """Recognize if or match nodes in supplied statements and their descendants.

    Args:
        statements: Statement roots to walk, including any nested scopes beneath them.

    Returns:
        True when a supplied statement or any descendant is an if or match node; false otherwise.
    """
    return any(isinstance(node, ast.If | ast.Match) for statement in statements for node in ast.walk(statement))


def _assertions_in(statements: list[ast.stmt]) -> list[ast.Assert]:
    """Collect assertions from the supplied statements and their descendants.

    Args:
        statements: Statement roots to walk without excluding nested scopes.

    Returns:
        Assertion nodes in statement order and each statement's AST walk order; an empty list when none are found.
    """
    return [node for statement in statements for node in ast.walk(statement) if isinstance(node, ast.Assert)]


def _is_guard_statement(statement: ast.stmt) -> bool:
    """Identify a direct control-flow exit or recognized skip-call statement.

    Args:
        statement: Single branch-body statement to classify; nested statements are not searched.

    Returns:
        True for return, raise, break, continue or a recognized standalone skip call; false otherwise.
    """
    if isinstance(statement, ast.Return | ast.Raise | ast.Break | ast.Continue):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        return _call_name(statement.value) in _GUARD_SKIP_CALLS
    return False


def _call_name(call: ast.Call) -> str:
    """Extract a call target's available name and attribute components.

    Args:
        call: Call whose callee syntax is read without import or runtime resolution.

    Returns:
        A dotted spelling, trailing attributes for an unsupported root, or an empty string when no components are named.
    """
    parts: list[str] = []
    node: ast.AST = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))
