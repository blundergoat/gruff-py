"""End-to-end CLI test for gitignore-aware source discovery (M12)."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _file_paths_in_report(output: str) -> set[str]:
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
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--no-config", "."],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert not any("vendor/third_party.py" in p for p in paths), paths


@pytest.mark.usefixtures("project_with_gitignored_finding")
def test_include_ignored_surfaces_gitignored_findings() -> None:
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--no-config", "--include-ignored", "."],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert any("vendor/third_party.py" in p for p in paths), paths


def test_project_without_gitignore_behaves_normally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "src" / "app.py", "x = 1\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--no-config", "."],
    )

    assert result.exit_code == 0, result.output
    paths = _file_paths_in_report(result.output)
    assert any("src/app.py" in p for p in paths), paths
