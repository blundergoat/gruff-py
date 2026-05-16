"""Tests for parser diagnostics on non-fatal parse failures."""

import ast
from pathlib import Path
from typing import Any

import pytest

from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.source.source_file import SourceFile


def test_ast_value_error_is_reported_as_parse_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_path = tmp_path / "broken.py"
    source_path.write_text("value = 1\n", encoding="utf-8")

    def raise_value_error(*_args: Any, **_kwargs: Any) -> ast.AST:
        raise ValueError("field 'value' is required for Constant")

    monkeypatch.setattr(ast, "parse", raise_value_error)

    unit = PythonFileParser().parse(
        SourceFile(absolute_path=str(source_path), display_path="broken.py")
    )

    assert unit.tree is None
    assert len(unit.diagnostics) == 1
    assert unit.diagnostics[0].message == "field 'value' is required for Constant"
