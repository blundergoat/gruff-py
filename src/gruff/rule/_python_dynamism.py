"""Python dynamism allowlist (M04).

Helper used by dead-code and waste rules to suppress false positives caused
by Python's dynamic patterns: pytest fixtures, Click commands, Flask/FastAPI
routes, abstract base classes, Protocols, dataclasses, and ``__all__``
re-exports.

Each predicate is intentionally conservative — false negatives (missed
exemptions) are user-tunable via per-rule config; false positives are not
(they erode trust in the analyser, per `gruff-py/.goat-flow/footguns/`).

Each predicate takes the AST node plus optional context and returns True
when the node should be treated as "active" by the calling rule.
"""

import ast

# --- Decorator-recognition helpers -------------------------------------------

# Decorators whose presence on a function/method means that name IS referenced
# by an external framework — never flag the function as unused.
_FRAMEWORK_DECORATOR_HINTS: frozenset[str] = frozenset(
    {
        # pytest
        "fixture",
        "parametrize",
        "mark",  # @pytest.mark.skip, @pytest.mark.parametrize, etc.
        # Click
        "command",
        "group",
        "option",
        "argument",
        # Flask / FastAPI / Quart
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "websocket",
        # Django
        "register",
        # SQLAlchemy event listeners
        "listens_for",
        # ABCs / typing
        "abstractmethod",
        "abstractclassmethod",
        "abstractstaticmethod",
        "abstractproperty",
        "overload",
        "override",
        "final",
        # property family — @property setters/getters are framework-style
        "property",
        "setter",
        "getter",
        "deleter",
        # dataclass / attrs
        "dataclass",
        "attr",
        "attrs",
        "define",
        # cache / functools
        "cache",
        "lru_cache",
    }
)


def has_framework_decorator(node: ast.AST) -> bool:
    """True when *node* carries a decorator hint that implies external use.

    Matches both ``@fixture`` and ``@pytest.fixture`` shapes by checking the
    rightmost attribute / name. ``@app.route(...)`` matches ``route``.
    """
    decorators = getattr(node, "decorator_list", None) or []
    for d in decorators:
        name = _decorator_name(d)
        if name in _FRAMEWORK_DECORATOR_HINTS:
            return True
        # Also match suffix patterns like ``app.route``, ``router.get``
        # where the rightmost dot-segment is a hint.
        if "." in name and name.split(".")[-1] in _FRAMEWORK_DECORATOR_HINTS:
            return True
    return False


def _decorator_name(decorator: ast.AST) -> str:
    """Return a dotted form of *decorator* for matching.

    Examples:

    - ``@fixture`` -> ``fixture``
    - ``@pytest.fixture`` -> ``pytest.fixture``
    - ``@app.route("/users")`` -> ``app.route`` (Call wraps Attribute)
    - ``@router.get`` -> ``router.get``
    """
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_name(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""


# --- Base-class recognition --------------------------------------------------

# Class bases that imply the class is a framework hook target.
_FRAMEWORK_BASE_HINTS: frozenset[str] = frozenset(
    {
        "Protocol",
        "ABC",
        "ABCMeta",
        "TypedDict",
        "NamedTuple",
        "Enum",
        "IntEnum",
        "StrEnum",
        "Flag",
    }
)


def has_framework_base(cls: ast.ClassDef) -> bool:
    """True if *cls* extends a Protocol / ABC / TypedDict / Enum-like base."""
    for base in cls.bases:
        name = _decorator_name(base)
        if name in _FRAMEWORK_BASE_HINTS:
            return True
        if "." in name and name.split(".")[-1] in _FRAMEWORK_BASE_HINTS:
            return True
    return False


def has_dataclass_decorator(cls: ast.ClassDef) -> bool:
    """True if *cls* has @dataclass / @attrs.define / @attr.s family."""
    decorators = cls.decorator_list
    for d in decorators:
        name = _decorator_name(d)
        leaf = name.split(".")[-1]
        if leaf in {"dataclass", "define", "frozen", "attr", "attrs", "s"}:
            return True
    return False


# --- __all__ extraction ------------------------------------------------------


def module_all_names(tree: ast.AST) -> frozenset[str]:
    """Return the string names declared by a module-level ``__all__``.

    Only static lists/tuples of string constants are recognised. Dynamic
    constructions are treated as "no __all__" — conservative on purpose.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    return _string_seq(node.value)
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__all__"
            and node.value is not None
        ):
            return _string_seq(node.value)
    return frozenset()


def _string_seq(value: ast.AST) -> frozenset[str]:
    if not isinstance(value, ast.List | ast.Tuple):
        return frozenset()
    names: set[str] = set()
    for elt in value.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            names.add(elt.value)
    return frozenset(names)


# --- Method-shape recognition ------------------------------------------------


def is_abstract_method(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if *fn* is decorated as abstract.

    Recognises @abstractmethod / @abstractclassmethod / @abstractstaticmethod
    / @abstractproperty by their rightmost segment.
    """
    for d in fn.decorator_list:
        name = _decorator_name(d).split(".")[-1]
        if name in {
            "abstractmethod",
            "abstractclassmethod",
            "abstractstaticmethod",
            "abstractproperty",
        }:
            return True
    return False


def is_overload_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if *fn* is decorated with @typing.overload."""
    return any(_decorator_name(d).split(".")[-1] == "overload" for d in fn.decorator_list)


def is_protocol_method_stub(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]
) -> bool:
    """True if *fn* is a method inside a Protocol class with an empty body
    (the canonical ``def m(self): ...`` shape)."""
    if not parents:
        return False
    parent_cls = next((p for p in reversed(parents) if isinstance(p, ast.ClassDef)), None)
    if parent_cls is None or not has_framework_base(parent_cls):
        return False
    return _is_empty_body(fn.body)


def _is_empty_body(body: list[ast.stmt]) -> bool:
    """True if *body* is exactly ``pass`` or ``...`` (single Expr-Constant)."""
    if len(body) == 1:
        only = body[0]
        if isinstance(only, ast.Pass):
            return True
        if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant):
            return True
    # Allow [docstring, pass] or [docstring, ...] as also empty.
    if (
        len(body) == 2
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        second = body[1]
        if isinstance(second, ast.Pass):
            return True
        if isinstance(second, ast.Expr) and isinstance(second.value, ast.Constant):
            return True
    return False
