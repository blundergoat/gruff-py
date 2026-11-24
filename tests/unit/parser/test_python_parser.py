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
    """Report a ``ValueError`` from ``ast.parse`` as one parse diagnostic carrying its message, leaving no tree.

    Args:
        tmp_path: Holds the one-line module handed to the parser.
        monkeypatch: Replaces ``ast.parse`` with a stub that raises the malformed-node ValueError.

    Returns:
        None. Checks that the parser reports the stub's exact message once and produces no syntax tree.
    """
    source_path = tmp_path / "broken.py"
    source_path.write_text("value = 1\n", encoding="utf-8")

    def raise_value_error(*_args: Any, **_kwargs: Any) -> ast.AST:
        """Raise a fixed ValueError to exercise the parser's diagnostic path.

        Args:
            _args: Positional parser inputs accepted and ignored by the stub.
            _kwargs: Keyword parser inputs accepted and ignored by the stub.

        Returns:
            Never returns.

        Raises:
            ValueError: Always, with the fixed malformed-Constant message.
        """
        raise ValueError("field 'value' is required for Constant")

    monkeypatch.setattr(ast, "parse", raise_value_error)

    unit = PythonFileParser().parse(SourceFile(absolute_path=str(source_path), display_path="broken.py"))

    assert unit.tree is None
    assert len(unit.diagnostics) == 1
    assert unit.diagnostics[0].message == "field 'value' is required for Constant"


def _bounded_python_unit(tmp_path: Path) -> AnalysisUnit:
    """Exercise the parser fallback for Python source that exceeds a one-line CLI budget.

    Args:
        tmp_path: Directory the oversized source is written into.

    Returns:
        An analysis unit with no AST and a nonfatal bounded-deep-scan diagnostic.
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
    """Leave no tree for a source over the line bound, without counting a parse error, and mark the unit as bounded.

    Args:
        tmp_path: Receives the two-line module parsed under a one-line budget.

    Returns:
        None. Checks that parsing marks the unit as bounded and leaves no tree or parse error.
    """
    unit = _bounded_python_unit(tmp_path)

    assert unit.tree is None
    assert unit.has_parse_errors() is False
    assert unit.is_deep_scan_bounded() is True


def test_bounded_python_source_reports_a_nonfatal_budget_diagnostic(
    tmp_path: Path,
) -> None:
    """Describe a bounded source with a non-fatal ``bounded-deep-scan`` diagnostic naming its size, the CLI limits and the analysis that ran.

    Args:
        tmp_path: Receives the oversized module for this parse.

    Returns:
        None. Checks the diagnostic type, nonfatal status, and exact message.
    """
    unit = _bounded_python_unit(tmp_path)

    assert unit.diagnostics[0].type == "bounded-deep-scan"
    assert unit.diagnostics[0].non_fatal is True
    assert (
        unit.diagnostics[0].message == "path=large.py; lines=2; bytes=20; maxLines=1; maxBytes=10000; override=cli. "
        "Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, "
        "AST walking, and other deep script analysis were skipped."
    )


@pytest.mark.parametrize("separator", [b"\n", b"\r\n", b"\r"], ids=["lf", "crlf", "cr"])
def test_line_budget_counts_physical_lines_without_a_phantom_last_line(tmp_path: Path, separator: bytes) -> None:
    """Treat a two-line module at the exact budget as parseable under each newline convention.

    Args:
        tmp_path: Receives the Python module at the line limit.
        separator: Newline bytes used throughout the module, including after its last line.

    Returns:
        None. Checks for a real Python tree and an empty diagnostic list.
    """
    source_path = tmp_path / "module.py"
    source_path.write_bytes(separator.join((b"first = 1", b"second = 2", b"")))

    unit = PythonFileParser().parse(
        SourceFile(absolute_path=str(source_path), display_path="module.py"),
        DeepScanBudget(enabled=True, max_lines=2, max_bytes=10_000, override="cli"),
    )

    assert isinstance(unit.tree, ast.Module)
    assert unit.diagnostics == ()


def test_non_python_text_never_enters_deep_scan_guard(tmp_path: Path) -> None:
    """Return no tree and no diagnostic for a text file, even under a one-line, one-byte deep-scan budget.

    Args:
        tmp_path: Receives the two-line ``.env`` file parsed as text.

    Returns:
        None. Checks that parsing the text file leaves the tree absent and diagnostics empty under the configured budget.
    """
    source_path = tmp_path / ".env"
    source_path.write_text("A=1\nB=2\n", encoding="utf-8")

    unit = PythonFileParser().parse(
        SourceFile(absolute_path=str(source_path), display_path=".env", type="text"),
        DeepScanBudget(enabled=True, max_lines=1, max_bytes=1, override="config"),
    )

    assert unit.tree is None
    assert unit.diagnostics == ()


def test_read_error_omits_absolute_host_path(tmp_path: Path) -> None:
    """Keep host filesystem paths out of read-error diagnostics emitted for missing or unreadable files.

    Args:
        tmp_path: Temporary project directory holding the absent file path.

    Returns:
        None. Asserts the parse diagnostic describes the OS failure without exposing the absolute path.
    """
    missing_path = tmp_path / "gone.py"
    unit = PythonFileParser().parse(
        SourceFile(absolute_path=str(missing_path), display_path="gone.py", type="python"),
    )

    assert unit.tree is None
    assert len(unit.diagnostics) == 1
    assert unit.diagnostics[0].message.startswith("read error: ")
    assert str(tmp_path) not in unit.diagnostics[0].message
