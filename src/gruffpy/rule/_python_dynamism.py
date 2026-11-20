"""Python dynamism allowlist.

Helper used by dead-code and waste rules to suppress false positives caused
by Python's dynamic patterns: pytest fixtures, Click commands, Flask/FastAPI
routes, abstract base classes, Protocols, dataclasses, and ``__all__``
re-exports.

Each predicate is intentionally conservative - false negatives (missed
exemptions) are user-tunable via per-rule config; false positives are not
(they erode trust in the analyser, per `gruff-py/.goat-flow/learning-loop/footguns/`).

Each predicate takes the AST node plus optional context and returns True
when the node should be treated as "active" by the calling rule.
"""

import ast

# Decorators whose presence on a function/method means that name IS referenced
# by an external framework - never flag the function as unused.
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
        # Flask / FastAPI / Starlette app lifecycle hooks - registered by the
        # decorator and invoked by the framework, never called by name.
        "on_event",  # @app.on_event("startup"|"shutdown")
        "before_request",
        "after_request",
        "teardown_request",
        "teardown_appcontext",
        "errorhandler",
        "context_processor",
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
        # property family - @property setters/getters are framework-style
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
    """Return whether a node carries a decorator hint that implies external use.

    Match names directly or by their final dotted segment; decorator calls are matched by their callee.

    Args:
        node: AST node whose decorator_list is inspected when present; a missing or empty list yields False.

    Returns:
        True when any decorator matches a known framework hook.
    """
    decorators = getattr(node, "decorator_list", None) or []
    for d in decorators:
        name = _decorator_name(d)
        if name in _FRAMEWORK_DECORATOR_HINTS:
            return True
        if "." in name and name.split(".")[-1] in _FRAMEWORK_DECORATOR_HINTS:
            return True
    return False


def _decorator_name(decorator: ast.AST) -> str:
    """Return a dotted expression name for framework-marker matching.

    Args:
        decorator: Expression to name. Callers pass decorator expressions, class base expressions and the test of an if statement. A call is named by
            its callee, so call arguments are ignored.

    Returns:
        Dotted name such as pytest.fixture or app.route. When an attribute's base cannot be named, for example a subscript, only the attribute name is
        returned. Any other expression shape gives an empty string.
    """
    if isinstance(decorator, ast.Call):
        return _decorator_name(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_name(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""


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
        # pydantic - same role as TypedDict for naming/size purposes: the class
        # IS a schema declaration, so its field shape is part of its API contract.
        "BaseModel",
        "RootModel",
    }
)


def has_framework_base(cls: ast.ClassDef) -> bool:
    """Return whether a class extends a Protocol, ABC, TypedDict, or Enum-like base.

    Returns:
        True when any base class matches a known framework-style base.
    """
    for base in cls.bases:
        name = _decorator_name(base)
        if name in _FRAMEWORK_BASE_HINTS:
            return True
        if "." in name and name.split(".")[-1] in _FRAMEWORK_BASE_HINTS:
            return True
    return False


def is_test_class(cls: ast.ClassDef) -> bool:
    """Return whether a class is a unittest TestCase or a pytest-style Test* class.

    Recognised shapes:

    - ``class FooTest(unittest.TestCase):`` / ``class FooTest(TestCase):`` /
      ``class FooTest(IsolatedAsyncioTestCase):`` - anything ending in
      ``TestCase`` (covers most subclassed test bases).
    - ``class TestFoo:`` - pytest's name-based collection convention; a
      fallback when the import chain is opaque or the test base is
      provided by a fixture/conftest.

    Used by size rules (size.public-method-count, size.attribute-count) and
    other rules that should not flag legitimate test scaffolding. Mirrors the
    logic in ``_test_quality_node_helper._is_unittest_testcase`` but adds the
    pytest name fallback.

    Returns:
        True when the class is a recognised unittest or pytest test class.
    """
    for base in cls.bases:
        name = _decorator_name(base)
        if name in {"TestCase", "unittest.TestCase", "IsolatedAsyncioTestCase"}:
            return True
        if name.endswith(".TestCase") or name.endswith("TestCase"):
            return True
    return cls.name.startswith("Test")


def has_dataclass_decorator(cls: ast.ClassDef) -> bool:
    """Return whether a class has a dataclass or attrs-style decorator.

    Returns:
        True when the class decorator list marks generated instance behavior.
    """
    decorators = cls.decorator_list
    for d in decorators:
        name = _decorator_name(d)
        leaf = name.split(".")[-1]
        if leaf in {"dataclass", "define", "frozen", "attr", "attrs", "s"}:
            return True
    return False


def module_all_names(tree: ast.AST) -> frozenset[str]:
    """Extract literal export names from the first module-level __all__ assignment.

    List and tuple literals contribute their string elements; other expression shapes contribute no names.

    Args:
        tree: AST root to inspect; a non-module root produces no names.

    Returns:
        Names from the first plain or valued annotated __all__ assignment, with non-string elements skipped;
        an empty frozen set when none are extracted.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    return _string_seq(node.value)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "__all__" and node.value is not None:
            return _string_seq(node.value)
    return frozenset()


def _string_seq(value: ast.AST) -> frozenset[str]:
    """Collect the string constants from a list or tuple literal assigned to a module-level __all__.

    Args:
        value: Expression on the right-hand side of a plain or annotated __all__ assignment.

    Returns:
        Frozen set of the literal's string constant elements, with non-string elements skipped. The set is empty when value is not a list or tuple
        literal, for example a concatenation or a call.
    """
    if not isinstance(value, ast.List | ast.Tuple):
        return frozenset()
    names: set[str] = set()
    for elt in value.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            names.add(elt.value)
    return frozenset(names)


def is_abstract_method(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a function is decorated as abstract.

    Recognises @abstractmethod / @abstractclassmethod / @abstractstaticmethod
    / @abstractproperty by their rightmost segment.

    Args:
        fn: Function node to inspect.

    Returns:
        True when a decorator marks the function as abstract.
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
    """Recognize an overload decorator by its final name segment, without resolving the import.

    Args:
        fn: Function definition whose decorators are checked for an overload name.

    Returns:
        True when the function has an overload decorator.
    """
    return any(_decorator_name(d).split(".")[-1] == "overload" for d in fn.decorator_list)


def is_type_checking_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> bool:
    """Recognize ellipsis stubs directly under a syntactic TYPE_CHECKING guard.

    Args:
        fn: Function to check for a body consisting of an ellipsis and an optional leading docstring.
        parents: Outer-to-inner ancestors, used to distinguish the else branch.

    Returns:
        True for a stub directly in an if body whose name or attribute test renders as TYPE_CHECKING or typing.TYPE_CHECKING via _decorator_name.
    """
    if not parents or not isinstance(parents[-1], ast.If):
        return False
    branch = parents[-1]
    if fn not in branch.body or not isinstance(branch.test, ast.Name | ast.Attribute):
        return False
    if _decorator_name(branch.test) not in {"TYPE_CHECKING", "typing.TYPE_CHECKING"}:
        return False
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    return len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and body[0].value.value is Ellipsis


def is_pluggy_hookspec(fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> bool:
    """Recognize an empty module hook from its imported pluggy marker.

    Args:
        fn: Function whose project prefix must match a literal marker binding.
        parents: Outer-to-inner ancestors; methods and nested functions do not qualify.

    Returns:
        True when the same module proves the hook's pluggy project namespace.
    """
    if not parents or not isinstance(parents[-1], ast.Module) or not _is_empty_body(fn.body):
        return False
    return any(fn.name.startswith(project + "_") for project in _pluggy_projects(parents[-1]))


def _pluggy_projects(module: ast.Module) -> set[str]:
    """Collect literal project names from module-level pluggy marker assignments.

    Args:
        module: Parsed source; absent or overwritten imports prove no projects.

    Returns:
        Project names for which the module binds a pluggy hook marker.
    """
    marker_names = _pluggy_marker_names(module) - _module_shadowed_marker_names(module)
    projects: set[str] = set()
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
            continue
        value = statement.value
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name) or value.func.id not in marker_names:
            continue
        if len(value.args) != 1 or value.keywords:
            continue
        project = value.args[0]
        if isinstance(project, ast.Constant) and isinstance(project.value, str) and project.value:
            projects.add(project.value)
    return projects


def _pluggy_marker_names(module: ast.Module) -> set[str]:
    """Find local names bound by top-level imports of HookspecMarker from pluggy.

    Args:
        module: Source module to check for absolute imports of HookspecMarker.

    Returns:
        The imported marker's local names, including explicit aliases.
    """
    return {
        alias.asname or alias.name
        for statement in module.body
        if isinstance(statement, ast.ImportFrom) and statement.module == "pluggy" and statement.level == 0
        for alias in statement.names
        if alias.name == "HookspecMarker"
    }


def _module_shadowed_marker_names(module: ast.Module) -> set[str]:
    """Find bindings that prevent trusting a pluggy marker import.

    Args:
        module: Source module; nested assignments are conservatively included.

    Returns:
        Names that disqualify a matching marker alias. Includes names assigned anywhere and top-level function, class and import bindings.
        Absolute from-imports of pluggy are excluded from the import check.
    """
    rebound = {node.id for statement in module.body for node in ast.walk(statement) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    rebound.update(statement.name for statement in module.body if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef))
    rebound.update(
        alias.asname or alias.name.split(".")[0]
        for statement in module.body
        if isinstance(statement, ast.Import | ast.ImportFrom)
        and not (isinstance(statement, ast.ImportFrom) and statement.module == "pluggy" and statement.level == 0)
        for alias in statement.names
    )
    return rebound


def is_protocol_method_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef, parents: list[ast.AST]) -> bool:
    """Return whether a function is an empty Protocol method stub.

    Args:
        fn: Function node to inspect.
        parents: Parent chain for locating the owning class.

    Returns:
        True for canonical ``def m(self): ...`` methods inside Protocol-like
        classes.
    """
    if not parents:
        return False
    parent_cls = next((p for p in reversed(parents) if isinstance(p, ast.ClassDef)), None)
    if parent_cls is None or not has_framework_base(parent_cls):
        return False
    return _is_empty_body(fn.body)


def _is_empty_body(body: list[ast.stmt]) -> bool:
    """Recognize placeholder bodies containing one pass or constant expression, optionally after a string docstring.

    A lone string or ellipsis counts; an empty list, other statement shapes and bodies longer than two statements do not.

    Args:
        body: Statement list of a function definition, as passed by the waste.empty-function rule and by the Protocol stub and pluggy hookspec
            predicates.

    Returns:
        True when the body matches one of the placeholder shapes; False for any other statement list.
    """
    if len(body) == 1:
        only = body[0]
        if isinstance(only, ast.Pass):
            return True
        if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant):
            return True
    if len(body) == 2 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        second = body[1]
        if isinstance(second, ast.Pass):
            return True
        if isinstance(second, ast.Expr) and isinstance(second.value, ast.Constant):
            return True
    return False
