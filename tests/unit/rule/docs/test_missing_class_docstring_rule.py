from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.missing_class_docstring_rule import MissingClassDocstringRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_class_with_docstring_skipped():
    """Report nothing for a class with a docstring.

    Returns:
        None. Checks that the rule emits no findings for the documented class.
    """
    src = 'class C:\n    """A class."""\n    pass\n'
    assert MissingClassDocstringRule().analyse(make_unit(src), default_ctx()) == []


def test_class_without_docstring_emits():
    """Report an undocumented class once, asking for a brief intent description rather than saying it has no docstring.

    Returns:
        None. Checks the finding count, class symbol, and message wording.
    """
    src = "class C:\n    x = 1\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C"
    assert "needs a brief intent description" in findings[0].message
    assert "has no docstring" not in findings[0].message


def test_protocol_subclass_skipped():
    """Report nothing for an undocumented Protocol subclass.

    Returns:
        None. Asserts that the class docstring rule returns an empty findings list for P.
    """
    src = "from typing import Protocol\n\nclass P(Protocol):\n    def m(self) -> None: ...\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert findings == []


def test_dataclass_without_docstring_emits_by_default():
    """Report an undocumented dataclass once under the default options.

    Returns:
        None. Checks that the rule reports exactly one finding for D.
    """
    src = "from dataclasses import dataclass\n\n@dataclass\nclass D:\n    x: int\n"
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "D"


def test_dataclass_can_be_exempted_by_config():
    """Report nothing for an undocumented dataclass when class_dataclass_exempt is set.

    Returns:
        None. Asserts that the enabled exemption leaves the findings list empty.
    """
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
    """Report an undocumented nested class once, as Outer.Inner.

    Returns:
        None. Asserts that the only finding names Outer.Inner.
    """
    src = '"""Module."""\n\nclass Outer:\n    """Outer doc."""\n    class Inner:\n        x = 1\n'
    findings = MissingClassDocstringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "Outer.Inner"


def test_inline_class_inside_test_method_is_exempt():
    """Report nothing for an inline stub class defined inside a test method in a test file.

    Returns:
        None. Asserts that Metrics inside test_reads_metric produces no class-docstring finding.
    """
    src = (
        "class MetricsTest:\n"
        '    """Suite doc."""\n'
        "    def test_reads_metric(self):\n"
        "        class Metrics:\n"
        "            value = 1\n"
        "        assert Metrics.value == 1\n"
    )
    findings = MissingClassDocstringRule().analyse(make_unit(src, "tests/test_metrics.py"), default_ctx())
    assert findings == []


def test_top_level_test_class_and_production_local_class_still_warn():
    """Keep warning on undocumented top-level test classes and function-local classes in production files.

    Returns:
        None. Asserts both top-level test classes and production local classes report warning severity.
    """
    test_src = "class MetricsTest:\n    pass\n"
    prod_src = 'def build():\n    """Build."""\n    class Local:\n        value = 1\n    return Local\n'
    test_findings = MissingClassDocstringRule().analyse(make_unit(test_src, "tests/test_metrics.py"), default_ctx())
    prod_findings = MissingClassDocstringRule().analyse(make_unit(prod_src, "src/metrics.py"), default_ctx())
    assert [(f.symbol, f.severity.value) for f in test_findings] == [("MetricsTest", "warning")]
    assert [(f.symbol, f.severity.value) for f in prod_findings] == [("build.Local", "warning")]
