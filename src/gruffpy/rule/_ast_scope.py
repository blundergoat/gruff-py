"""Scope-limited AST traversal shared by per-function rules.

A per-function rule that walks a function body with bare ``ast.walk`` descends
into nested ``def`` / ``class`` / ``lambda`` bodies. Because every nested scope
is also visited in its own pass, that double-counts findings and misattributes
their source to the enclosing scope. These helpers walk a single lexical scope,
stopping at nested-scope boundaries so each scope is analysed exactly once.

``complexity/_walks.py`` keeps an equivalent pair confined to the complexity
rules; this module is the cross-pillar home for rules outside that package.
"""

import ast
from collections.abc import Iterator

_SCOPE_BOUNDARIES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def walk_function_scope(function: ast.AST) -> Iterator[ast.AST]:
    """Yield *function* and every descendant that belongs to its own scope.

    The function node is yielded first (so callers may inspect its arguments or
    decorators), then traversal descends through the body but stops at any
    nested ``def`` / ``class`` / ``lambda`` - those are analysed in their own
    pass over the module.

    Args:
        function: Function-like node whose own scope should be walked.

    Returns:
        Iterator over the function node and its non-nested descendants.
    """
    yield function
    for child in ast.iter_child_nodes(function):
        yield from _walk_within_scope(child)


def walk_statement_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Yield *node* and its descendants, treating *node* as scope-bounded.

    Unlike :func:`walk_function_scope`, when *node* is itself a nested scope
    (a statement that is a ``def`` / ``class``) it is yielded but not descended
    into. Use this when walking individual statements that may themselves
    introduce a nested scope.

    Args:
        node: Statement (or expression) whose enclosing scope should be walked.

    Returns:
        Iterator over *node* and its descendants outside any nested scope.
    """
    yield from _walk_within_scope(node)


def _walk_within_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Yield node and its descendants in pre-order, never descending into a def, async def, class or lambda.

    The boundary check also applies to node itself: a def, async def, class or lambda node passed in is yielded alone. walk_function_scope therefore
    calls this on each child of the function rather than on the function node, so that the function's own body is still walked.

    Everything beneath a boundary node is skipped, including its decorators, argument defaults and base classes.

    Args:
        node: Root of the walk, yielded first; when it is a def, async def, class or lambda node its children are skipped.

    Yields:
        Each AST node in pre-order: node itself, then every descendant outside a nested scope, with each nested def, async def, class or lambda node
        included but its contents excluded.
    """
    yield node
    if isinstance(node, _SCOPE_BOUNDARIES):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_within_scope(child)
