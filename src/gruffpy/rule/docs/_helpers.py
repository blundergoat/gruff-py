"""Shared helpers for documentation-pillar rules.

Public-vs-private detection, decorator pattern recognition (property setter /
deleter), and parameter-name extraction for signature matching. Lives next to
the rules that consume it so the docs pillar's policy isn't smeared across the
broader ``_python_dynamism`` helper.
"""

import ast
from collections.abc import Iterator

from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition

EVERY_CALLABLE_OPTION = "everyCallable"
"""Rule option that widens a docs rule to every callable; off by default until the port's own code passes it."""


def every_callable_enabled(context: RuleContext, definition: RuleDefinition) -> bool:
    """Return whether a docs rule's ``everyCallable`` option is on for this run.

    Args:
        context: Rule execution context carrying the resolved rule settings.
        definition: Definition of the rule that reads the option.

    Returns:
        True only when the project configuration turned the option on.
    """
    return bool(context.settings_for(definition).options.get(EVERY_CALLABLE_OPTION, False))


def is_in_documentation_scope(name: str, *, every_callable: bool) -> bool:
    """Return whether a callable's name puts it in a docs rule's scope.

    Dunder hooks stay out of scope. Underscore-private names come into scope
    only when the rule's ``everyCallable`` option is on.

    Args:
        name: Identifier of the function or method.
        every_callable: Whether the rule's ``everyCallable`` option is on.

    Returns:
        True when the rule should inspect the callable.
    """
    if is_dunder(name):
        return False
    return every_callable or not name.startswith("_")


def own_body_nodes(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Yield every node in a function's own body, without entering nested scopes.

    A nested function, lambda or class owns its own ``return`` and ``yield``, so
    the walk stops at them.

    Args:
        fn: Function node whose body should be walked.

    Yields:
        Each node that belongs to the function's own scope.
    """
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def is_generator(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function yields from its own body.

    Args:
        fn: Function node to inspect.

    Returns:
        True when the function's own scope contains ``yield`` or ``yield from``.
    """
    return any(isinstance(node, ast.Yield | ast.YieldFrom) for node in own_body_nodes(fn))


def returns_value(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function's own body returns or yields a value.

    A bare ``return`` and ``return None`` are not values.

    Args:
        fn: Function node to inspect.

    Returns:
        True when the function returns a value or is a generator.
    """
    for node in own_body_nodes(fn):
        if isinstance(node, ast.Yield | ast.YieldFrom):
            return True
        if isinstance(node, ast.Return) and node.value is not None and not _is_none_constant(node.value):
            return True
    return False


def quoted_names(names: list[str]) -> str:
    """Return names as a quoted English list, such as ``'x', 'y' and 'z'``.

    Args:
        names: Identifiers to list, in order; at least one.

    Returns:
        The quoted names joined with commas and a final "and".
    """
    quoted = [repr(name) for name in names]
    if len(quoted) == 1:
        return quoted[0]
    return f"{', '.join(quoted[:-1])} and {quoted[-1]}"


def _is_none_constant(node: ast.AST) -> bool:
    """Return whether an expression is the literal ``None``."""
    return isinstance(node, ast.Constant) and node.value is None


def is_dunder(name: str) -> bool:
    """Return whether a name is a Python double-underscore hook.

    Args:
        name: Identifier to inspect.

    Returns:
        True for names such as ``__init__`` and ``__repr__``.
    """
    return name.startswith("__") and name.endswith("__") and len(name) >= 4


def is_public(name: str) -> bool:
    """Return whether a name should be treated as public documentation surface.

    Dunder names (``__x__``) are framework hooks, not public API; this returns
    False for them so the caller can decide whether to treat them specially.

    Args:
        name: Identifier to inspect.

    Returns:
        True when the name is public and not a dunder hook.
    """
    if is_dunder(name):
        return False
    return not name.startswith("_")


def is_test_file(display_path: str) -> bool:
    """Return whether a display path points at a conventional Python test file.

    Args:
        display_path: Project-relative source path shown in findings.

    Returns:
        True when the path is under a tests directory or is a top-level
        ``test_*.py`` file.
    """
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")


def is_property_setter_or_deleter(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function is a property setter or deleter.

    Setters and deleters inherit documentation from the getter; the docs pillar
    treats them as exempt from missing-docstring checks.

    Args:
        fn: Function node to inspect.

    Returns:
        True when any decorator resolves to ``setter`` or ``deleter``.
    """
    for d in fn.decorator_list:
        name = _decorator_name(d)
        leaf = name.split(".")[-1] if "." in name else ""
        if leaf in {"setter", "deleter"}:
            return True
    return False


def signature_param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return the user-facing parameter names for a function.

    Excludes ``self`` / ``cls`` when present as the first positional arg.
    Includes positional-only, regular positional, keyword-only, ``*args``,
    and ``**kwargs`` names so docstring matching covers all signature slots.

    Args:
        fn: Function node whose signature should be inspected.

    Returns:
        Parameter names that should appear in function documentation.
    """
    args = fn.args
    names: list[str] = []
    positional = list(args.posonlyargs) + list(args.args)
    if positional and positional[0].arg in {"self", "cls"}:
        positional = positional[1:]
    names.extend(a.arg for a in positional)
    names.extend(a.arg for a in args.kwonlyargs)
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def has_none_only_return(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function's return annotation is exactly ``None``.

    Used by ``docs.missing-return-doc`` to skip void-typed functions.
    Functions without any return annotation are NOT considered void here -
    the rule already requires an explicit non-None annotation before firing.

    Args:
        fn: Function node whose return annotation should be inspected.

    Returns:
        True when the return annotation is explicitly ``None``.
    """
    annotation = fn.returns
    if annotation is None:
        return False
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True
    return isinstance(annotation, ast.Name) and annotation.id == "None"


def has_return_annotation(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function declares any return annotation.

    Args:
        fn: Function node whose signature should be inspected.

    Returns:
        True when the function has a return annotation.
    """
    return fn.returns is not None


def has_raise_in_body(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function body contains a direct ``raise`` statement.

    Walks control-flow blocks but stops at nested function/lambda boundaries so
    a wrapped helper's ``raise`` does not trigger the outer rule.

    Args:
        fn: Function node whose body should be inspected.

    Returns:
        True when a non-nested raise statement appears in the function body.
    """
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        if isinstance(node, ast.Raise):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _decorator_name(decorator: ast.AST) -> str:
    """Return a dotted form of *decorator* (``app.route`` for ``@app.route(...)``)."""
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_name(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""
