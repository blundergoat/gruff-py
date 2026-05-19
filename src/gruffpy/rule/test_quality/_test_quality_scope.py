"""Scope value object for the test-quality pillar.

Encapsulates whether an ``ast.FunctionDef`` (or AsyncFunctionDef) lives in a
recognised test scope: a module-level ``test_*`` function, a method of a
``Test*`` class (pytest collection), or a method of a ``unittest.TestCase``
subclass. The async flag tells rules whether they're inside an async test.
"""

from dataclasses import dataclass
from enum import StrEnum


class TestScopeKind(StrEnum):
    BARE_TEST_FUNC = "bare_test_func"  # def test_* at module level
    PYTEST_TEST_METHOD = "pytest_test_method"  # method of class Test*
    UNITTEST_TEST_METHOD = "unittest_test_method"  # method of unittest.TestCase
    CONFTEST = "conftest"  # any function in conftest.py
    NON_TEST = "non_test"


@dataclass(frozen=True, slots=True)
class TestScope:
    """Resolved test-function context.

    Attributes:
        kind: Matched pytest or unittest collection convention.
        is_async: Whether the test function is async.
        parent_class_name: Enclosing test class name, if class-scoped.
    """

    kind: TestScopeKind
    is_async: bool
    parent_class_name: str | None = None  # for class-scoped tests, the enclosing class name
