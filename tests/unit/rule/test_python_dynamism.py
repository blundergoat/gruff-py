import ast

import pytest

from gruffpy.rule._python_dynamism import (
    has_dataclass_decorator,
    has_framework_base,
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
    module_all_names,
)


def _first_fn(source: str) -> ast.FunctionDef:
    """Return the first top-level, non-async function definition in source.

    Args:
        source: Python source to parse.

    Returns:
        That function definition.

    Raises:
        AssertionError: The source has no top-level, non-async function.
    """
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function")


def _first_class(source: str) -> ast.ClassDef:
    """Return the first top-level class definition in source.

    Args:
        source: Python source to parse.

    Returns:
        That class definition.

    Raises:
        AssertionError: The source has no top-level class.
    """
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            return node
    raise AssertionError("no class")


def _parse_with_parents(source: str) -> ast.Module:
    """Parse source and link every non-root AST node to its parent.

    Args:
        source: Python source to parse.

    Returns:
        The parsed module tree with parent links for enclosing-scope checks.
    """
    tree = ast.parse(source)
    # Match production parsing so rules can inspect enclosing scopes.
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST nodes lack a declared parent attribute.
    return tree


def test_no_decorator_returns_false():
    """Recognise no framework decorator on an undecorated function.

    Returns:
        None. Checks that the decorator detector returns False for an undecorated function.
    """
    assert has_framework_decorator(_first_fn("def f(): pass\n")) is False


def test_pytest_fixture_decorator():
    """Recognise @pytest.fixture as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the parsed function decorated with @pytest.fixture.
    """
    src = "import pytest\n@pytest.fixture\ndef thing(): return 1\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_bare_fixture_decorator():
    """Recognise a bare @fixture imported from pytest as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the parsed function decorated with bare @fixture.
    """
    src = "from pytest import fixture\n@fixture\ndef thing(): return 1\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_flask_route_decorator():
    """Recognise a Flask-style @app.route call as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the parsed @app.route call decorator.
    """
    src = "@app.route('/users')\ndef users(): return []\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_router_get_decorator():
    """Recognise a @router.get call as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the parsed @router.get call decorator.
    """
    src = "@router.get('/items')\ndef get_items(): return []\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_fastapi_on_event_decorator():
    """Recognise @app.on_event on an async function as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the async function's @app.on_event decorator.
    """
    src = '@app.on_event("startup")\nasync def startup_event(): ...\n'
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.AsyncFunctionDef))
    assert has_framework_decorator(fn) is True


def test_flask_before_request_decorator():
    """Recognise a Flask-style @app.before_request as a framework decorator.

    Returns:
        None. Checks that the detector returns True for the parsed @app.before_request decorator.
    """
    src = "@app.before_request\ndef load_user(): ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_flask_errorhandler_decorator():
    """Recognise Flask's @app.errorhandler call as a framework decorator.

    Returns:
        None. Checks that the framework decorator classifier accepts the Flask error handler for status 404.
    """
    src = "@app.errorhandler(404)\ndef not_found(error): ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_abstractmethod_decorator():
    """Treat @abstractmethod as a framework decorator that marks an abstract method.

    Returns:
        None. Checks that both the framework decorator and abstract method predicates accept the decorated method.
    """
    src = "from abc import abstractmethod\n@abstractmethod\ndef m(self): ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True
    assert is_abstract_method(fn) is True


def test_overload_decorator():
    """Recognise a @overload function as an overload stub.

    Returns:
        None. Checks that the overload-stub predicate accepts the decorated declaration.
    """
    src = "from typing import overload\n@overload\ndef f(x: int) -> int: ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert is_overload_stub(fn) is True


def test_unrelated_decorator_returns_false():
    """Recognise no framework decorator in an unrelated custom decorator.

    Returns:
        None. Checks that a custom decorator leaves the framework decorator predicate false.
    """
    src = "@my_custom_decorator\ndef thing(): pass\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is False


def test_protocol_base():
    """Recognise a Protocol base as a framework base.

    Returns:
        None. Checks that a class inheriting from Protocol is classified as having a framework base.
    """
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self): ...\n"
    assert has_framework_base(_first_class(src)) is True


def test_abc_base():
    """Recognise an ABC base as a framework base.

    Returns:
        None. Checks that a class inheriting from ABC is classified as having a framework base.
    """
    src = "from abc import ABC\nclass A(ABC):\n    pass\n"
    assert has_framework_base(_first_class(src)) is True


def test_no_base_returns_false():
    """Recognise no framework base on a class without bases.

    Returns:
        None. Checks that a class with no explicit bases leaves the framework base predicate false.
    """
    src = "class C:\n    pass\n"
    assert has_framework_base(_first_class(src)) is False


def test_unrelated_base():
    """Recognise no framework base in an unrelated base class.

    Returns:
        None. Checks that inheriting from MyClass leaves the framework base predicate false.
    """
    src = "class C(MyClass):\n    pass\n"
    assert has_framework_base(_first_class(src)) is False


def test_dataclass_decorator():
    """Recognise @dataclass as a dataclass decorator.

    Returns:
        None. Checks that the dataclass decorator predicate accepts a class using the standard-library decorator.
    """
    src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    x: int = 0\n"
    assert has_dataclass_decorator(_first_class(src)) is True


def test_attrs_define_decorator():
    """Recognise @attrs.define as a dataclass decorator.

    Returns:
        None. Checks that the dataclass decorator predicate accepts a class decorated with attrs.define.
    """
    src = "import attrs\n@attrs.define\nclass C:\n    x = 0\n"
    assert has_dataclass_decorator(_first_class(src)) is True


def test_module_all_extracts_string_list():
    """Read the names in a list assigned to __all__.

    Returns:
        None. Checks that all listed names are extracted, including names without matching definitions in the fixture.
    """
    src = "__all__ = ['foo', 'bar', 'baz']\ndef foo(): pass\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo", "bar", "baz"})


def test_module_all_extracts_string_tuple():
    """Read the names in a tuple assigned to __all__.

    Returns:
        None. Checks that the extracted names are exactly the two entries in the tuple.
    """
    src = "__all__ = ('foo', 'bar')\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo", "bar"})


def test_module_all_annotated_assignment():
    """Read the names in an annotated __all__ assignment.

    Returns:
        None. Checks that the annotated assignment contributes foo as the sole extracted name.
    """
    src = "__all__: list[str] = ['foo']\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo"})


def test_module_all_missing_returns_empty():
    """Return no names when the module does not assign __all__.

    Returns:
        None. Checks that the extractor returns an empty set when the module has no __all__ assignment.
    """
    src = "def f(): pass\n"
    assert module_all_names(ast.parse(src)) == frozenset()


def test_module_all_dynamic_returns_empty():
    """Return no names when __all__ is built by a call.

    Returns:
        None. Checks that an assignment from a call contributes no statically extracted names.
    """
    src = "__all__ = list_of_names()\n"
    assert module_all_names(ast.parse(src)) == frozenset()


def test_protocol_method_stub_recognised():
    """Recognise an ellipsis-bodied method of a Protocol class as a protocol stub.

    Returns:
        None. Checks that the stub predicate accepts the ellipsis-bodied method with its Protocol class in the parent chain.
    """
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self):\n        ...\n"
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert is_protocol_method_stub(method, parents=[tree, cls]) is True


def test_non_protocol_method_not_stub():
    """Recognise no protocol stub in an ellipsis-bodied method of an ordinary class.

    Returns:
        None. Checks that an ellipsis body alone does not make an ordinary class method a protocol stub.
    """
    src = "class C:\n    def m(self): ...\n"
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert is_protocol_method_stub(method, parents=[tree, cls]) is False


@pytest.mark.parametrize(
    "source, predicate, expected",
    [
        (
            "from pluggy import HookspecMarker\n"
            'def HookspecMarker(project): return project\nhookspec = HookspecMarker("pytest")\ndef pytest_event(arg): ...\n',
            "is_pluggy_hookspec",
            False,
        ),
        ("if TYPE_CHECKING():\n    def declared(arg): ...\n", "is_type_checking_stub", False),
        ('from pluggy import HookspecMarker as Marker\nhookspec = Marker("pytest")\ndef pytest_event(arg): ...\n', "is_pluggy_hookspec", True),
        ("from pluggy import HookspecMarker\nhookspec = HookspecMarker(project)\ndef pytest_event(arg): ...\n", "is_pluggy_hookspec", False),
        (
            'from pluggy import HookspecMarker\nhookspec = HookspecMarker("pytest")\nclass Plugin:\n    def pytest_event(self, arg): ...\n',
            "is_pluggy_hookspec",
            False,
        ),
        (
            'from pluggy import HookspecMarker\nhookspec = HookspecMarker("pytest")\ndef pytest_event(arg):\n    return None\n',
            "is_pluggy_hookspec",
            False,
        ),
        ("if TYPE_CHECKING:\n    if DEBUG:\n        def declared(arg): ...\n", "is_type_checking_stub", False),
        ("if other.TYPE_CHECKING:\n    def declared(arg): ...\n", "is_type_checking_stub", False),
        ("if TYPE_CHECKING:\n    def declared(arg):\n        ...\n        return None\n", "is_type_checking_stub", False),
    ],
    ids=[
        "shadowed-hookspec-marker",
        "called-type-checking",
        "aliased-hookspec-marker",
        "non-literal-hookspec-project",
        "hookspec-method-not-module-function",
        "hookspec-with-body",
        "nested-type-checking-guard",
        "attribute-type-checking",
        "type-checking-stub-with-body",
    ],
)
def test_declaration_guard_boundaries(source: str, predicate: str, expected: bool) -> None:
    """Check that only the function in the aliased pluggy marker case passes its declaration guard.

    Args:
        source: Module declaring pytest_event or declared; the cases vary markers, guards, nesting and bodies.
        predicate: Name of the guard function under test.
        expected: Whether the guard should accept the declaration.

    Returns:
        None. Checks the selected guard against the expected boolean for the declaration and its enclosing scopes.
    """
    from gruffpy.rule import _python_dynamism
    from gruffpy.rule.size._lines import parent_chain

    tree = _parse_with_parents(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in {"pytest_event", "declared"})
    assert getattr(_python_dynamism, predicate)(function, parent_chain(function)) is expected
