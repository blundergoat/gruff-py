from gruff.rule.docs.missing_class_docstring_rule import MissingClassDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_class_with_docstring_skipped():
    src = 'class C:\n    """A class."""\n    pass\n'
    assert MissingClassDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_class_without_docstring_emits():
    src = "class C:\n    x = 1\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C"


def test_protocol_subclass_skipped():
    src = "from typing import Protocol\n\nclass P(Protocol):\n    def m(self) -> None: ...\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_dataclass_skipped_by_default():
    src = "from dataclasses import dataclass\n\n@dataclass\nclass D:\n    x: int\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_nested_class_emits():
    src = '"""Module."""\n\nclass Outer:\n    """Outer doc."""\n    class Inner:\n        x = 1\n'
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "Outer.Inner"
