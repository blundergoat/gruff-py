import ast

import pytest

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


def test_compound_main_guard_is_clean():
    src = 'import sys\n\nif __name__ == "__main__" and __package__ is None:\n    sys.path.insert(0, "/opt/lib")\n'
    assert _analyse(src) == []


def test_else_branch_of_main_guard_fires():
    # The else branch runs when the module is imported, so mutation there is
    # not exempt even though the guard marks the file as a script.
    src = 'import sys\n\nif __name__ == "__main__":\n    pass\nelse:\n    sys.path.insert(0, "/opt/lib")\n'
    findings = _analyse(src)
    assert len(findings) == 1


_SIBLING_IMPORT_SCRIPT = (
    "import sys\n"
    "from pathlib import Path\n\n"
    "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
    "from app.heuristics import score_role\n\n\n"
    "def main():\n"
    "    return score_role()\n"
)


@pytest.mark.parametrize(
    ("source", "display_path"),
    [
        (f'{_SIBLING_IMPORT_SCRIPT}\n\nif __name__ == "__main__":\n    main()\n', "probe/eval_role_heuristic.py"),
        (f"#!/usr/bin/env python3\n{_SIBLING_IMPORT_SCRIPT}", "probe/eval_role_heuristic.py"),
        (_SIBLING_IMPORT_SCRIPT, "scripts/eval-role-heuristic.py"),
        (_SIBLING_IMPORT_SCRIPT, "bin/eval_role_heuristic.py"),
        (_SIBLING_IMPORT_SCRIPT, "tools/release/eval_role_heuristic.py"),
    ],
    ids=["main-guard-anywhere", "shebang", "scripts-directory", "bin-directory", "tools-directory"],
)
def test_top_level_insert_in_a_standalone_script_is_clean(source: str, display_path: str) -> None:
    """Exempt the downstream brief's repo-local scripts, whose insert must run before their sibling imports.

    Args:
        source: Script whose top-level insert precedes the import that needs it.
        display_path: Project-relative path of the script.
    """
    assert _analyse(source, display_path=display_path) == []


def test_top_level_insert_in_an_importable_module_still_fires():
    """Keep full strength for a library module with no guard, shebang, or script directory."""
    findings = _analyse(_SIBLING_IMPORT_SCRIPT, display_path="src/app/eval_role_heuristic.py")
    assert [finding.metadata["method"] for finding in findings] == ["insert"]


def test_insert_inside_a_function_of_a_guarded_module_still_fires():
    """Report flask's ``cli.py`` shape: a guarded module whose function is called by the modules importing it."""
    src = (
        "import sys\n\n\n"
        "def prepare_import(path):\n"
        "    if sys.path[0] != path:\n"
        "        sys.path.insert(0, path)\n\n\n"
        'if __name__ == "__main__":\n'
        '    prepare_import(".")\n'
    )
    findings = _analyse(src, display_path="src/flask/cli.py")
    assert [finding.line for finding in findings] == [6]


def test_definition_is_advisory_high_confidence_design():
    definition = RuntimeSysPathMutationRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "high"
    assert definition.pillar.value == "design"
    assert definition.default_enabled is True
