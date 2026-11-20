"""Shared helpers for complexity rules.

`iter_functions` walks an AST and yields every function-like node (FunctionDef,
AsyncFunctionDef, Lambda) with its parent chain. `body_nodes` iterates a
function body without descending into nested function definitions - nested
functions get their own findings, so per-function rules must stop at the
nested-def boundary.
"""

import ast
from collections.abc import Iterator
from typing import cast

FunctionLike = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
_FUNCTION_CACHE_ATTR = "_gruffpy_function_nodes"


def iter_functions(tree: ast.AST) -> Iterator[FunctionLike]:
    """Yield cached function-like nodes, or collect them in ast.walk order and cache the tuple on the root.

    Args:
        tree: AST root to inspect and cache on; later AST changes do not invalidate its cached tuple.

    Yields:
        Function, async function and lambda nodes in the cached or newly collected order.
    """
    cached = getattr(tree, _FUNCTION_CACHE_ATTR, None)
    if isinstance(cached, tuple):
        yield from cast(tuple[FunctionLike, ...], cached)
        return

    functions = tuple(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda))
    setattr(tree, _FUNCTION_CACHE_ATTR, functions)
    yield from functions


def body_nodes(fn: FunctionLike) -> Iterator[ast.AST]:
    """Walk a function body without descending into nested scopes.

    Walks every AST node in the body, but stops at any nested
    function/class definition (those are scored independently).

    Yields the function node itself first (so callers may inspect its
    arguments / decorators), then every descendant outside nested scopes.

    Args:
        fn: Function-like node whose body should be walked.

    Returns:
        Iterator over the function-like node and non-nested descendants.
    """
    if isinstance(fn, ast.Lambda):
        # Lambdas have no nested defs to skip; just walk the body expression.
        yield fn
        yield from ast.walk(fn.body)
        return

    yield fn
    for child in fn.body:
        yield from _walk_skip_nested(child)


def _walk_skip_nested(node: ast.AST) -> Iterator[ast.AST]:
    """Walk a subtree depth-first, yielding a nested function, lambda, or class node but not its contents.

    The boundary check runs after the node is yielded, so a nested definition node is still produced, but none of its children are visited, including
    its decorators, default argument values, and body.

    Args:
        node: Root of the subtree to walk, typically one statement from a function body; it is always yielded first, even when it is itself a nested
            definition.

    Yields:
        Each AST node in depth-first pre-order, following ast.iter_child_nodes order below each node.
    """
    yield node
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_skip_nested(child)


def is_wildcard_pattern(pattern: ast.pattern) -> bool:
    """Identify an unbound wildcard for cyclomatic counting; named catch-alls still count as decisions.

    Args:
        pattern: Pattern node from a match case.

    Returns:
        True only for MatchAs with both pattern and name unset; False for every other pattern.
    """
    return isinstance(pattern, ast.MatchAs) and pattern.pattern is None and pattern.name is None
