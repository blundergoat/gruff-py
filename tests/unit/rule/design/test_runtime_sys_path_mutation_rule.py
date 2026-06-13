import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.design.runtime_sys_path_mutation_rule import RuntimeSysPathMutationRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "src/pkg/module.py") -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    rule = RuntimeSysPathMutationRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str, display_path: str = "src/pkg/module.py"):
    return RuntimeSysPathMutationRule().analyse(_unit(source, display_path), _ctx())


def test_module_level_insert_zero_fires_with_metadata():
    src = 'import sys\n\nsys.path.insert(0, "/opt/lib")\n'
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["method"] == "insert"
    assert findings[0].metadata["argumentPosition"] == 0
    assert "shadows every later top-level import" in findings[0].message


def test_append_inside_library_function_fires():
    src = "import sys\n\ndef setup_paths(root):\n    sys.path.append(root)\n"
    findings = _analyse(src)
    assert len(findings) == 1
    assert findings[0].metadata["method"] == "append"
    assert "argumentPosition" not in findings[0].metadata


def test_insert_inside_main_block_is_clean():
    src = 'import sys\n\nif __name__ == "__main__":\n    sys.path.insert(0, "/opt/lib")\n'
    assert _analyse(src) == []


def test_reversed_main_guard_is_clean():
    src = 'import sys\n\nif "__main__" == __name__:\n    sys.path.insert(0, "/opt/lib")\n'
    assert _analyse(src) == []


def test_append_in_tests_directory_is_clean():
    src = 'import sys\n\nsys.path.append("/helpers")\n'
    assert _analyse(src, display_path="tests/helpers.py") == []


def test_conftest_is_clean():
    src = 'import sys\n\nsys.path.insert(0, "/src")\n'
    assert _analyse(src, display_path="conftest.py") == []


def test_other_list_named_path_is_clean():
    src = 'import os\n\nclass Config:\n    path = []\n\nConfig.path.insert(0, "x")\n'
    assert _analyse(src) == []


def test_definition_is_advisory_high_confidence_design():
    definition = RuntimeSysPathMutationRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "high"
    assert definition.pillar.value == "design"
    assert definition.default_enabled is True
