import ast

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
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function")


def _first_class(source: str) -> ast.ClassDef:
    for node in ast.parse(source).body:
        if isinstance(node, ast.ClassDef):
            return node
    raise AssertionError("no class")


# --- has_framework_decorator -------------------------------------------------


def test_no_decorator_returns_false():
    assert has_framework_decorator(_first_fn("def f(): pass\n")) is False


def test_pytest_fixture_decorator():
    src = "import pytest\n@pytest.fixture\ndef thing(): return 1\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_bare_fixture_decorator():
    src = "from pytest import fixture\n@fixture\ndef thing(): return 1\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_flask_route_decorator():
    src = "@app.route('/users')\ndef users(): return []\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_router_get_decorator():
    src = "@router.get('/items')\ndef get_items(): return []\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True


def test_abstractmethod_decorator():
    src = "from abc import abstractmethod\n@abstractmethod\ndef m(self): ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is True
    assert is_abstract_method(fn) is True


def test_overload_decorator():
    src = "from typing import overload\n@overload\ndef f(x: int) -> int: ...\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert is_overload_stub(fn) is True


def test_unrelated_decorator_returns_false():
    src = "@my_custom_decorator\ndef thing(): pass\n"
    fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef))
    assert has_framework_decorator(fn) is False


# --- has_framework_base ------------------------------------------------------


def test_protocol_base():
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self): ...\n"
    assert has_framework_base(_first_class(src)) is True


def test_abc_base():
    src = "from abc import ABC\nclass A(ABC):\n    pass\n"
    assert has_framework_base(_first_class(src)) is True


def test_no_base_returns_false():
    src = "class C:\n    pass\n"
    assert has_framework_base(_first_class(src)) is False


def test_unrelated_base():
    src = "class C(MyClass):\n    pass\n"
    assert has_framework_base(_first_class(src)) is False


# --- has_dataclass_decorator -------------------------------------------------


def test_dataclass_decorator():
    src = "from dataclasses import dataclass\n@dataclass\nclass C:\n    x: int = 0\n"
    assert has_dataclass_decorator(_first_class(src)) is True


def test_attrs_define_decorator():
    src = "import attrs\n@attrs.define\nclass C:\n    x = 0\n"
    assert has_dataclass_decorator(_first_class(src)) is True


# --- module_all_names --------------------------------------------------------


def test_module_all_extracts_string_list():
    src = "__all__ = ['foo', 'bar', 'baz']\ndef foo(): pass\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo", "bar", "baz"})


def test_module_all_extracts_string_tuple():
    src = "__all__ = ('foo', 'bar')\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo", "bar"})


def test_module_all_annotated_assignment():
    src = "__all__: list[str] = ['foo']\n"
    assert module_all_names(ast.parse(src)) == frozenset({"foo"})


def test_module_all_missing_returns_empty():
    src = "def f(): pass\n"
    assert module_all_names(ast.parse(src)) == frozenset()


def test_module_all_dynamic_returns_empty():
    src = "__all__ = list_of_names()\n"
    assert module_all_names(ast.parse(src)) == frozenset()


# --- is_protocol_method_stub -------------------------------------------------


def test_protocol_method_stub_recognised():
    src = "from typing import Protocol\nclass P(Protocol):\n    def m(self):\n        ...\n"
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert is_protocol_method_stub(method, parents=[tree, cls]) is True


def test_non_protocol_method_not_stub():
    src = "class C:\n    def m(self): ...\n"
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    method = cls.body[0]
    assert isinstance(method, ast.FunctionDef)
    assert is_protocol_method_stub(method, parents=[tree, cls]) is False
