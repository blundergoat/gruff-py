import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.attribute_count_rule import AttributeCountRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``x.py``.

    Args:
        source: Python source to parse.

    Returns:
        A unit for ``x.py`` whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 15) -> RuleContext:
    """Build a rule context with the attribute count rule enabled at an error threshold.

    Args:
        threshold: Value the rule allows before it reports; defaults to 15.

    Returns:
        A context whose config enables only the attribute count rule at that threshold.
    """
    rule = AttributeCountRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_few_attributes_emits_no_finding():
    """Report nothing for a class with two annotated attributes."""
    source = "class C:\n    a: int = 1\n    b: int = 2\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []


def test_annotated_class_attributes_counted():
    """Count twenty annotated class attributes, reported once as an advisory lower-band finding against a threshold of 15."""
    body = "\n".join(f"    a{i}: int = {i}" for i in range(20))
    source = f"class C:\n{body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attributes"] == 20
    # Twenty attributes against the limit of 15 sit under one and a half times it, so the finding is a notice.
    assert findings[0].severity == Severity.ADVISORY
    assert findings[0].metadata["limitBand"] == "lower"


def test_init_self_assignments_counted():
    """Count twenty attributes assigned on ``self`` in ``__init__``, reported once."""
    init_body = "\n".join(f"        self.a{i} = {i}" for i in range(20))
    source = f"class C:\n    def __init__(self):\n{init_body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attributes"] == 20


def test_class_body_and_init_dedupe_by_name():
    """Report nothing when five class-body names reassigned in ``__init__`` plus ten new ones leave fifteen distinct attributes."""
    # 5 class-body annotated + 5 self.a0..a4 reassignments + 10 more self.b0..b9
    body = "\n".join(f"    a{i}: int = {i}" for i in range(5))
    init = "\n".join([f"        self.a{i} = {i}" for i in range(5)] + [f"        self.b{i} = {i}" for i in range(10)])
    source = f"class C:\n{body}\n    def __init__(self):\n{init}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    # 5 (a0..a4) + 10 (b0..b9) = 15 -> at threshold, no finding
    assert findings == []


def test_class_above_error_threshold_emits_error():
    """Give the first finding error severity and a count of 30 for thirty annotated attributes."""
    body = "\n".join(f"    a{i}: int = {i}" for i in range(30))
    source = f"class C:\n{body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["attributes"] == 30


def test_class_attribute_plain_assignment_counted():
    """Count three plain class-body assignments in the first finding, against a threshold of 2."""
    source = "class C:\n    a = 1\n    b = 2\n    c = 3\n"
    # 3 attributes; threshold 2 -> warning
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx(threshold=2))
    assert findings[0].metadata["attributes"] == 3


def test_tuple_self_assignment_collects_all_names():
    """Count all three names of one tuple assignment on ``self``, against a threshold of 2."""
    source = "class C:\n    def __init__(self):\n        self.a, self.b, self.c = 1, 2, 3\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx(threshold=2))
    assert findings[0].metadata["attributes"] == 3


def test_typeddict_is_exempt():
    """Report nothing for a ``TypedDict`` with twenty fields."""
    # TypedDict's job IS to enumerate fields; counting them as "too many
    # attributes" misses the intent.
    body = "\n".join(f"    a{i}: int" for i in range(20))
    source = f"from typing import TypedDict\nclass S(TypedDict, total=False):\n{body}\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []


def test_dataclass_is_exempt():
    """Report nothing for a dataclass with twenty fields."""
    body = "\n".join(f"    a{i}: int = {i}" for i in range(20))
    source = f"from dataclasses import dataclass\n@dataclass\nclass C:\n{body}\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []


def test_pydantic_basemodel_is_exempt():
    """Report nothing for a pydantic ``BaseModel`` with twenty fields."""
    body = "\n".join(f"    a{i}: int = {i}" for i in range(20))
    source = f"from pydantic import BaseModel\nclass S(BaseModel):\n{body}\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []


def test_unittest_testcase_is_exempt():
    """Report nothing for a ``unittest.TestCase`` subclass that assigns twenty attributes in ``__init__``."""
    init_body = "\n".join(f"        self.a{i} = {i}" for i in range(20))
    source = f"import unittest\nclass MyTest(unittest.TestCase):\n    def __init__(self):\n{init_body}\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []
