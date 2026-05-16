import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.generic_function_rule import GenericFunctionRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx(options: dict | None = None) -> RuleContext:
    rule = GenericFunctionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True, options=options or {})}
        ),
    )


def test_process_fires():
    src = "def process(x): return x\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "process"


def test_handle_fires():
    src = "def handle(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_do_fires():
    src = "def do(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_process_payment_does_not_fire():
    src = "def process_payment(x): return x\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_handle_request_does_not_fire():
    src = "def handle_request(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_method_generic_fires():
    src = "class C:\n    def execute(self): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.execute"


def test_non_generic_does_not_fire():
    src = "def calculate(): return 1\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_configurable_replacement():
    src = "def calculate(): return 1\n"
    findings = GenericFunctionRule().analyse(
        _unit(src), _ctx(options={"genericFunctions": ["calculate"]})
    )
    assert len(findings) == 1


def test_definition():
    d = GenericFunctionRule().definition()
    assert d.id == "naming.generic-function"
