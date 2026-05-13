"""Shared helpers for complexity rules.

`iter_functions` walks an AST and yields every function-like node (FunctionDef,
AsyncFunctionDef, Lambda) with its parent chain. `body_nodes` iterates a
function body without descending into nested function definitions — nested
functions get their own findings, so per-function rules must stop at the
nested-def boundary.
"""

import ast
from collections.abc import Iterator

FunctionLike = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


def iter_functions(tree: ast.AST) -> Iterator[FunctionLike]:
    """Yield every function-like node in *tree*, in document order."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            yield node


def body_nodes(fn: FunctionLike) -> Iterator[ast.AST]:
    """Walk *fn*'s body, yielding every AST node, but stop at any nested
    function/class definition (those are scored independently).

    Yields the function node itself first (so callers may inspect its
    arguments / decorators), then every descendant outside nested scopes.
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
    yield node
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_skip_nested(child)


def is_wildcard_pattern(pattern: ast.pattern) -> bool:
    """True for ``case _:`` and any pattern that is the bare-name catch-all.

    ``MatchAs(pattern=None, name=None)`` is the bare ``_`` (no binding).
    Named catch-alls like ``case x:`` bind a name and are NOT wildcards
    in the cyclomatic-counting sense — they are still decisions.
    """
    return isinstance(pattern, ast.MatchAs) and pattern.pattern is None and pattern.name is None
