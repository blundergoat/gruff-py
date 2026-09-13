"""Tests for parser diagnostics on non-fatal parse failures."""

import ast
from pathlib import Path
from typing import Any

import pytest

from gruffpy.config.analysis_config import DeepScanBudget
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.source.source_file import SourceFile


def test_ast_value_error_is_reported_as_parse_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_path = tmp_path / "broken.py"
    source_path.write_text("value = 1\n", encoding="utf-8")

    def raise_value_error(*_args: Any, **_kwargs: Any) -> ast.AST:
        """Stub for ``ast.parse`` that surfaces the canonical CPython post-3.12 shape error.

        Real CPython raises ``ValueError`` (not ``SyntaxError``) for this
        family of malformed AST node - the parser's diagnostic path must
        catch both.

        Returns:
            Never returns - always raises.

        Raises:
            ValueError: Always, mimicking CPython's malformed-Constant error.
        """
        raise ValueError("field 'value' is required for Constant")

    monkeypatch.setattr(ast, "parse", raise_value_error)

    unit = PythonFileParser().parse(SourceFile(absolute_path=str(source_path), display_path="broken.py"))

    assert unit.tree is None
    assert len(unit.diagnostics) == 1
    assert unit.diagnostics[0].message == "field 'value' is required for Constant"


def _bounded_python_unit(tmp_path: Path) -> AnalysisUnit:
    """Parse a source that crosses the line bound, so the budget degrades it before the AST.

    Args:
        tmp_path: Directory the oversized source is written into.

    Returns:
        The parsed unit, bounded by a one-line CLI budget.
    """
    source_path = tmp_path / "large.py"
    source_path.write_text("value = 1\nvalue = 2\n", encoding="utf-8")
    return PythonFileParser().parse(
        SourceFile(absolute_path=str(source_path), display_path="large.py"),
        DeepScanBudget(enabled=True, max_lines=1, max_bytes=10_000, override="cli"),
    )


def test_python_source_over_either_bound_degrades_before_ast(
    tmp_path: Path,
) -> None:
    unit = _bounded_python_unit(tmp_path)

    assert unit.tree is None
    assert unit.has_parse_errors() is False
    assert unit.is_deep_scan_bounded() is True


def test_bounded_python_source_reports_a_nonfatal_budget_diagnostic(
    tmp_path: Path,
) -> None:
    unit = _bounded_python_unit(tmp_path)

    assert unit.diagnostics[0].type == "bounded-deep-scan"
    assert unit.diagnostics[0].non_fatal is True
    assert (
        unit.diagnostics[0].message == "path=large.py; lines=3; bytes=20; maxLines=1; maxBytes=10000; override=cli. "
        "Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, "
        "AST walking, and other deep script analysis were skipped."
    )


def test_non_python_text_never_enters_deep_scan_guard(tmp_path: Path) -> None:
    source_path = tmp_path / ".env"
    source_path.write_text("A=1\nB=2\n", encoding="utf-8")

    unit = PythonFileParser().parse(
        SourceFile(absolute_path=str(source_path), display_path=".env", type="text"),
        DeepScanBudget(enabled=True, max_lines=1, max_bytes=1, override="config"),
    )

    assert unit.tree is None
    assert unit.diagnostics == ()
