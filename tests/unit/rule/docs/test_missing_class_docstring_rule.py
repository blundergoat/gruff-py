from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.missing_class_docstring_rule import MissingClassDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_class_with_docstring_skipped():
    src = 'class C:\n    """A class."""\n    pass\n'
    assert MissingClassDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_class_without_docstring_emits():
    src = "class C:\n    x = 1\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C"
    assert "needs a brief intent description" in findings[0].message
    assert "has no docstring" not in findings[0].message


def test_protocol_subclass_skipped():
    src = "from typing import Protocol\n\nclass P(Protocol):\n    def m(self) -> None: ...\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_dataclass_without_docstring_emits_by_default():
    src = "from dataclasses import dataclass\n\n@dataclass\nclass D:\n    x: int\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "D"


def test_dataclass_can_be_exempted_by_config():
    src = "from dataclasses import dataclass\n\n@dataclass\nclass D:\n    x: int\n"
    rule = MissingClassDocstringRule()
    ctx = RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={
                rule.definition().id: RuleSettings(
                    enabled=True,
                    options={"class_dataclass_exempt": True},
                )
            }
        ),
    )
    findings = rule.analyse(make_unit(src), ctx)
    assert findings == []


def test_nested_class_emits():
    src = '"""Module."""\n\nclass Outer:\n    """Outer doc."""\n    class Inner:\n        x = 1\n'
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "Outer.Inner"
