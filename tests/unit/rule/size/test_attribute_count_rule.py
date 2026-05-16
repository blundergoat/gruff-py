import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.attribute_count_rule import AttributeCountRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 15, error: int = 25) -> RuleContext:
    rule = AttributeCountRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_few_attributes_emits_no_finding():
    source = "class C:\n    a: int = 1\n    b: int = 2\n"
    assert AttributeCountRule().analyse(_make_unit(source), _ctx()) == []


def test_annotated_class_attributes_counted():
    body = "\n".join(f"    a{i}: int = {i}" for i in range(20))
    source = f"class C:\n{body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attributes"] == 20
    assert findings[0].severity == Severity.WARNING


def test_init_self_assignments_counted():
    init_body = "\n".join(f"        self.a{i} = {i}" for i in range(20))
    source = f"class C:\n    def __init__(self):\n{init_body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attributes"] == 20


def test_class_body_and_init_dedupe_by_name():
    # 5 class-body annotated + 5 self.a0..a4 reassignments + 10 more self.b0..b9
    body = "\n".join(f"    a{i}: int = {i}" for i in range(5))
    init = "\n".join(
        [f"        self.a{i} = {i}" for i in range(5)]
        + [f"        self.b{i} = {i}" for i in range(10)]
    )
    source = f"class C:\n{body}\n    def __init__(self):\n{init}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    # 5 (a0..a4) + 10 (b0..b9) = 15 -> at threshold, no finding
    assert findings == []


def test_class_above_error_threshold_emits_error():
    body = "\n".join(f"    a{i}: int = {i}" for i in range(30))
    source = f"class C:\n{body}\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx())
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["attributes"] == 30


def test_class_attribute_plain_assignment_counted():
    source = "class C:\n    a = 1\n    b = 2\n    c = 3\n"
    # 3 attributes; threshold 2 -> warning
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx(warning=2, error=10))
    assert findings[0].metadata["attributes"] == 3


def test_tuple_self_assignment_collects_all_names():
    source = "class C:\n    def __init__(self):\n        self.a, self.b, self.c = 1, 2, 3\n"
    findings = AttributeCountRule().analyse(_make_unit(source), _ctx(warning=2, error=10))
    assert findings[0].metadata["attributes"] == 3


def test_definition_uses_default_thresholds():
    d = AttributeCountRule().definition()
    assert d.id == "size.attribute-count"
    assert d.default_thresholds == {"warning": 15, "error": 25}
