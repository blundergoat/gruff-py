import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.confusing_name_rule import ConfusingNameRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx(options: dict | None = None) -> RuleContext:
    rule = ConfusingNameRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True, options=options or {})}
        ),
    )


def test_handler_class_fires():
    src = "class Handler:\n    pass\n"
    findings = ConfusingNameRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "Handler"


def test_manager_class_fires():
    src = "class Manager:\n    pass\n"
    findings = ConfusingNameRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_suffix_use_does_not_fire():
    src = "class UserService:\n    pass\nclass EventHandler:\n    pass\n"
    findings = ConfusingNameRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_unrelated_class_does_not_fire():
    src = "class User:\n    pass\n"
    findings = ConfusingNameRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_configurable_extra_vocabulary():
    src = "class FooBar:\n    pass\n"
    findings = ConfusingNameRule().analyse(
        _unit(src),
        _ctx(options={"confusingNames": ["FooBar"]}),
    )
    assert len(findings) == 1


def test_configurable_replaces_defaults():
    # When options set, defaults no longer apply.
    src = "class Handler:\n    pass\n"
    findings = ConfusingNameRule().analyse(
        _unit(src),
        _ctx(options={"confusingNames": ["ZZZ"]}),
    )
    assert findings == []
