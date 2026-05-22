import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.unused_import_rule import UnusedImportRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    tree = ast.parse(source)
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = UnusedImportRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_unused_simple_import_fires():
    src = "import os\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "os"


def test_used_import_does_not_fire():
    src = "import os\nprint(os.getcwd())\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_unused_from_import_fires():
    src = "from os.path import join\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "join"


def test_used_from_import_does_not_fire():
    src = "from os.path import join\np = join('a', 'b')\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_aliased_import_uses_alias_name():
    src = "import numpy as np\nprint(np.array)\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_aliased_import_unused_fires():
    src = "import numpy as np\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "np"


def test_dotted_import_binds_top_level():
    # ``import a.b.c`` binds ``a`` locally.
    src = "import os.path\nprint(os.path.join('x', 'y'))\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_all_export_suppresses():
    src = "import os\n__all__ = ['os']\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_noqa_suppresses():
    src = "import os  # noqa: F401\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_init_py_is_skipped():
    src = "import os\nimport sys\n"
    findings = UnusedImportRule().analyse(_unit(src, display_path="pkg/__init__.py"), _ctx())
    assert findings == []


def test_star_import_not_counted():
    src = "from os import *\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_imported_decorator_used():
    src = "from functools import lru_cache\n@lru_cache\ndef f(): return 1\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_import_used_by_string_annotation_does_not_fire():
    src = """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gruffpy.rule.registry import RuleRegistry


def f(registry: "RuleRegistry") -> None:
    return None
"""

    findings = UnusedImportRule().analyse(_unit(src), _ctx())

    assert findings == []


def test_import_used_by_nested_string_annotation_does_not_fire():
    src = """
from gruffpy.rule.definition import RuleDefinition


def f() -> "list[RuleDefinition]":
    return []
"""

    findings = UnusedImportRule().analyse(_unit(src), _ctx())

    assert findings == []


def test_future_annotations_import_is_skipped():
    src = "from __future__ import annotations\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_future_import_does_not_mask_unrelated_unused_import():
    src = "from __future__ import annotations\nimport os\n"
    findings = UnusedImportRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "os"


def test_definition():
    d = UnusedImportRule().definition()
    assert d.id == "waste.unused-import"
