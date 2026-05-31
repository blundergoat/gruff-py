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
_GUARD_SKIP_CALLS: frozenset[str] = frozenset(
    {"pytest.skip", "skip", "self.skipTest", "unittest.skip"}
)


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
    if not _is_fixture_iterable(
        node.iter, _literal_collection_bindings(fn), _target_names(node.target)
    ):
        return False
    assertions = _assertions_in(node.body)
    return not assertions or all(assertion.msg is not None for assertion in assertions)


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
    bindings: set[str] = set()
    for scope in (_module_root(fn), fn):
        for statement in getattr(scope, "body", []):
            bindings.update(_literal_collection_targets(statement))
    return frozenset(bindings)


def _literal_collection_targets(statement: ast.stmt) -> set[str]:
    if isinstance(statement, ast.Assign) and _is_literal_collection(statement.value):
        return {
            target.id
            for target in statement.targets
            if isinstance(target, ast.Name) and _is_fixtureish_name(target.id)
        }
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
    current = node
    while hasattr(current, "parent"):
        current = current.parent
    return current


def _target_names(target: ast.expr) -> frozenset[str]:
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
    name = _call_name(call)
    if name in {"glob", "Path.glob", "Path.rglob", "Path.iterdir"}:
        return True
    if name in {"list", "set", "sorted", "tuple"} and call.args:
        first = call.args[0]
        return isinstance(first, ast.expr) and _is_fixture_iterable(first, bindings, target_names)
    return name.endswith((".glob", ".rglob", ".iterdir"))


def _is_literal_collection(expr: ast.AST) -> bool:
    return isinstance(expr, ast.List | ast.Tuple | ast.Set | ast.Dict)


def _is_fixtureish_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _FIXTURE_NAME_MARKERS)


def _contains_branch(statements: list[ast.stmt]) -> bool:
    return any(
        isinstance(node, ast.If | ast.Match)
        for statement in statements
        for node in ast.walk(statement)
    )


def _assertions_in(statements: list[ast.stmt]) -> list[ast.Assert]:
    return [
        node
        for statement in statements
        for node in ast.walk(statement)
        if isinstance(node, ast.Assert)
    ]


def _is_guard_statement(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Return | ast.Raise | ast.Break | ast.Continue):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        return _call_name(statement.value) in _GUARD_SKIP_CALLS
    return False


def _call_name(call: ast.Call) -> str:
    parts: list[str] = []
    node: ast.AST = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))
