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
    """Yield the function node and its descendants, stopping below nested defs, async defs, classes and lambdas.

    Arguments and decorators are visited; nested scope nodes are included but their contents are excluded.

    Args:
        function: Function-like node whose own scope should be walked.

    Returns:
        Iterator yielding the root and descendants, including nested scope nodes but excluding their children.
    """
    yield function
    for child in ast.iter_child_nodes(function):
        yield from _walk_within_scope(child)


def walk_statement_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Walk a statement or expression without entering nested defs, async defs, classes or lambdas.

    A root that introduces a scope is yielded alone; use this for individual statements that may define a nested scope.

    Args:
        node: Root statement or expression to traverse without entering nested scopes.

    Returns:
        Iterator yielding the root and descendants, including each nested scope boundary but excluding its children.
    """
    yield from _walk_within_scope(node)


def _walk_within_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Yield node and its descendants in pre-order, including nested scope boundaries but none of their children.

    A def, async def, class or lambda root is yielded alone; its body, decorators, argument defaults and base classes are excluded.

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
