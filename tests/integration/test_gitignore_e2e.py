"""End-to-end CLI test for gitignore-aware source discovery."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main


def _write(path: Path, text: str = "") -> None:
    """Write text to a file, creating any missing parent directories.

    Args:
        path: File to create or overwrite.
        text: UTF-8 content; empty by default.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _file_paths_in_report(output: str) -> set[str]:
    """Collect the file of every finding in a JSON report.

    Args:
        output: JSON text printed by ``analyse --format json``.

    Returns:
        The distinct finding file paths; empty when the report lists no findings.
    """
    payload = json.loads(output)
    return {f["file"] for f in payload.get("findings", [])}


@pytest.fixture
def project_with_gitignored_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp project: kept file is clean, ignored file has a known docstring finding.

    Args:
        tmp_path: Pytest-provided per-test directory.
        monkeypatch: Pytest monkeypatch fixture (used to ``chdir`` into the project).

    Returns:
        Project root path with ``.gitignore``, ``src/kept.py``, and an ignored
        ``vendor/third_party.py`` already written.
    """
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / ".gitignore", "vendor/\n")
    _write(tmp_path / "src" / "kept.py", '"""Kept module."""\n\nx = 1\n')
    _write(tmp_path / "vendor" / "third_party.py", "x = 1\n")
    return tmp_path


@pytest.mark.usefixtures("project_with_gitignored_finding")
def test_gitignored_file_does_not_appear_in_findings() -> None:
    """Leave findings in a gitignored ``vendor`` file out of a full-project report."""
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "."],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert not any("vendor/third_party.py" in p for p in paths), paths


@pytest.mark.usefixtures("project_with_gitignored_finding")
def test_include_ignored_surfaces_gitignored_findings() -> None:
    """Report findings in the gitignored ``vendor`` file when ``--include-ignored`` is passed."""
    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-ignored",
            ".",
        ],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert any("vendor/third_party.py" in p for p in paths), paths


def test_project_without_gitignore_behaves_normally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report findings in an ordinary source file when the project has no ``.gitignore``.

    Args:
        tmp_path: Project root holding only ``src/app.py``, a module without a docstring.
        monkeypatch: Changes into the project so the ``.`` operand is the project root.
    """
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "src" / "app.py", "x = 1\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "."],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert any("src/app.py" in p for p in paths), paths
