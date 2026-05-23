"""Shared line-counting helper for size pillar rules.

Defined by ADR-002. Returns the raw line span - decorator line through
`end_lineno`, inclusive - for every AST node the size pillar scores. Cross-impl
parity with gruff-php depends on this being the single source of truth.
"""

import ast

LineCountableNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda


def lines_for_size(node: LineCountableNode) -> int:
    """Return the raw line span of a node, inclusive of decorators and end line.

    Lambdas have no decorators; their span runs from `lineno` to `end_lineno`.
    For def/class nodes, the span runs from the first decorator's `lineno`
    (or the node's own `lineno` if no decorators) to `end_lineno`.

    Args:
        node: Function, class, async function, or lambda node to measure.

    Returns:
        Inclusive raw line span for size scoring.
    """
    end = node.end_lineno
    if end is None:
        # Defensive: Python >= 3.8 always populates end_lineno on top-level
        # nodes returned by ast.parse(). Falling back to lineno keeps the
        # helper non-crashing on the unlikely event of a node with only lineno.
        return 1

    start = node.lineno
    decorators = getattr(node, "decorator_list", None) or []
    if decorators:
        start = min(start, *(d.lineno for d in decorators))

    return end - start + 1


def qualified_symbol(node: ast.AST, parents: list[ast.AST]) -> str:
    """Return a qualified dotted name using a node's parent chain.

    Used by size rules so findings carry a stable `symbol` field
    (e.g. ``ClassA.method_b`` or ``module_func``). The parents list is the
    parent AST chain from outermost (Module) to innermost (immediate parent).

    Args:
        node: AST node whose symbol should be rendered.
        parents: Parent AST chain from outermost to immediate parent.

    Returns:
        Dotted symbol name, lambda marker, or ``<module>`` fallback.
    """
    parts: list[str] = []
    for ancestor in parents:
        name = getattr(ancestor, "name", None)
        if isinstance(name, str):
            parts.append(name)
    own = getattr(node, "name", None)
    if isinstance(own, str):
        parts.append(own)
    elif isinstance(node, ast.Lambda):
        parts.append(f"<lambda:{node.lineno}>")
    return ".".join(parts) if parts else "<module>"


def parent_chain(node: ast.AST) -> list[ast.AST]:
    """Walk parent links upward and return the ancestor chain.

    Walks `parent` links from a node and returns ancestors
    from outermost (closest to module) to immediate parent (excluding *node*).

    Requires the parser to have attached `parent` attributes (the gruff-py
    parser does this in `_attach_parents`).

    Args:
        node: AST node whose ancestors should be returned.

    Returns:
        Ancestor chain from module-adjacent parent to immediate parent.
    """
    chain: list[ast.AST] = []
    current = getattr(node, "parent", None)
    while current is not None:
        chain.append(current)
        current = getattr(current, "parent", None)
    chain.reverse()
    return chain
