"""Shared helpers for documentation-pillar rules.

Public-vs-private detection, decorator pattern recognition (property setter /
deleter), and parameter-name extraction for signature matching. Lives next to
the rules that consume it so the docs pillar's policy isn't smeared across the
broader ``_python_dynamism`` helper.
"""

import ast


def is_dunder(name: str) -> bool:
    """True for ``__init__`` / ``__repr__`` / etc. — framework hook names."""
    return name.startswith("__") and name.endswith("__") and len(name) >= 4


def is_public(name: str) -> bool:
    """True when *name* does not start with an underscore.

    Dunder names (``__x__``) are framework hooks, not public API; this returns
    False for them so the caller can decide whether to treat them specially.
    """
    if is_dunder(name):
        return False
    return not name.startswith("_")


def is_property_getter(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if *fn* carries an ``@property`` decorator."""
    return any(_decorator_name(d).split(".")[-1] == "property" for d in fn.decorator_list)


def is_property_setter_or_deleter(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if *fn* is decorated as ``@<name>.setter`` or ``@<name>.deleter``.

    Setters and deleters inherit documentation from the getter; the docs pillar
    treats them as exempt from missing-docstring checks.
    """
    for d in fn.decorator_list:
        name = _decorator_name(d)
        leaf = name.split(".")[-1] if "." in name else ""
        if leaf in {"setter", "deleter"}:
            return True
    return False


def signature_param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return the user-facing parameter names for *fn*.

    Excludes ``self`` / ``cls`` when present as the first positional arg.
    Includes positional-only, regular positional, keyword-only, ``*args``,
    and ``**kwargs`` names so docstring matching covers all signature slots.
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


def returns_none_only(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when *fn*'s return annotation is exactly ``None``.

    Used by ``docs.missing-return-doc`` to skip void-typed functions.
    Functions without any return annotation are NOT considered void here —
    the rule already requires an explicit non-None annotation before firing.
    """
    annotation = fn.returns
    if annotation is None:
        return False
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True
    return isinstance(annotation, ast.Name) and annotation.id == "None"


def has_return_annotation(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when *fn* declares any return annotation at all."""
    return fn.returns is not None


def raises_in_body(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when *fn*'s body contains at least one ``raise`` statement.

    Walks control-flow blocks but stops at nested function/lambda boundaries so
    a wrapped helper's ``raise`` does not trigger the outer rule.
    """

    def visit(node: ast.AST) -> bool:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            return False
        if isinstance(node, ast.Raise):
            return True
        return any(visit(child) for child in ast.iter_child_nodes(node))

    return any(visit(stmt) for stmt in fn.body)


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
