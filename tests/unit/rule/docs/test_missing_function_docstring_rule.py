from gruff.rule.docs.missing_function_docstring_rule import MissingFunctionDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_function_with_docstring_skipped():
    src = 'def f():\n    """It does a thing."""\n    return 1\n'
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_function_without_docstring_emits():
    src = "def f():\n    return 1\n"
    findings = MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "f"


def test_private_function_skipped():
    src = "def _helper():\n    return 1\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_dunder_method_skipped():
    src = "class C:\n    def __init__(self): pass\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_abstract_method_skipped():
    src = "from abc import abstractmethod\n\nclass C:\n    @abstractmethod\n    def m(self): ...\n"
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_overload_stub_skipped():
    src = (
        "from typing import overload\n\n"
        "@overload\n"
        "def f(x: int) -> int: ...\n"
        "@overload\n"
        "def f(x: str) -> str: ...\n"
        "def f(x):\n"
        '    """Real impl."""\n'
        "    return x\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_property_getter_without_docstring_emits():
    src = "class C:\n    @property\n    def name(self):\n        return 'x'\n"
    findings = MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.name"


def test_property_setter_skipped():
    src = (
        "class C:\n"
        "    @property\n"
        "    def name(self):\n"
        '        """The name."""\n'
        "        return 'x'\n"
        "    @name.setter\n"
        "    def name(self, value):\n"
        "        self._name = value\n"
    )
    assert MissingFunctionDocstringRule().analyse(make_unit(src), default_ctx()) == []
