"""End-to-end tests: ``paths.ignore`` authority across modes, plus the ``check-ignore`` command."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

_FLAGGABLE_MODULE = (
    "import os\n\n\ndef process(a, b, c, d, e, f, g, h):\n    result = a + b\n    return result\n"
)
_DIFF_TOUCHING_IGNORED = (
    "diff --git a/skipme/bad.py b/skipme/bad.py\n"
    "--- a/skipme/bad.py\n"
    "+++ b/skipme/bad.py\n"
    "@@ -1 +1,2 @@\n"
    "+import sys\n"
)


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tmp project whose config ignores ``skipme/**`` over a findings-rich module.

    Args:
        tmp_path: Pytest-provided per-test directory.
        monkeypatch: Used to ``chdir`` into the project (analyse uses ``cwd``).

    Returns:
        Project root with ``.gruff-py.yaml``, an ignored ``skipme/bad.py``, and a kept file.
    """
    monkeypatch.chdir(tmp_path)
    _write(
        tmp_path / ".gruff-py.yaml",
        'schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - "skipme/**"\n',
    )
    _write(tmp_path / "skipme" / "bad.py", _FLAGGABLE_MODULE)
    _write(tmp_path / "src" / "kept.py", '"""Kept module."""\n\nx = 1\n')
    return tmp_path


@pytest.mark.usefixtures("project")
def test_control_ignored_file_is_flaggable_without_config() -> None:
    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-baseline",
            "--no-config",
            "skipme/bad.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["findings"]) > 0
    assert payload["ignoredPathDetails"] == []


@pytest.mark.usefixtures("project")
def test_analyse_explicit_ignored_arg_yields_no_findings_with_reason() -> None:
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "skipme/bad.py"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []
    assert payload["ignoredPathDetails"] == [
        {"path": "skipme/bad.py", "source": "config", "pattern": "skipme/**"}
    ]


@pytest.mark.usefixtures("project")
def test_analyse_diff_touching_ignored_file_yields_no_findings_with_reason() -> None:
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "--diff", "-"],
        input=_DIFF_TOUCHING_IGNORED,
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []
    assert any(
        detail["path"] == "skipme/bad.py" and detail["source"] == "config"
        for detail in payload["ignoredPathDetails"]
    )


@pytest.mark.usefixtures("project")
def test_include_ignored_still_honours_config_paths_ignore() -> None:
    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-baseline",
            "--include-ignored",
            "skipme/bad.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []
    assert any(detail["source"] == "config" for detail in payload["ignoredPathDetails"])


@pytest.mark.usefixtures("project")
def test_check_ignore_reports_config_match_and_non_match_as_json() -> None:
    result = CliRunner().invoke(
        main, ["check-ignore", "--format", "json", "skipme/bad.py", "src/kept.py"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == [
        {"path": "skipme/bad.py", "ignored": True, "source": "config", "pattern": "skipme/**"},
        {"path": "src/kept.py", "ignored": False, "source": None, "pattern": None},
    ]


@pytest.mark.usefixtures("project")
def test_check_ignore_exit_code_is_one_when_nothing_ignored() -> None:
    result = CliRunner().invoke(main, ["check-ignore", "--format", "json", "src/kept.py"])

    assert result.exit_code == 1, result.output


@pytest.mark.usefixtures("project")
def test_check_ignore_exit_code_is_two_with_no_paths() -> None:
    result = CliRunner().invoke(main, ["check-ignore", "--format", "json"])

    assert result.exit_code == 2


@pytest.mark.usefixtures("project")
def test_check_ignore_shares_engine_with_analyse() -> None:
    check = CliRunner().invoke(main, ["check-ignore", "--format", "json", "skipme/bad.py"])
    analyse = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "skipme/bad.py"],
    )

    check_verdict = json.loads(check.output)[0]
    analyse_payload = json.loads(analyse.output)
    assert check_verdict["ignored"] is True
    assert check_verdict["pattern"] == "skipme/**"
    assert analyse_payload["ignoredPathDetails"][0]["pattern"] == "skipme/**"


@pytest.mark.usefixtures("project")
def test_check_ignore_text_format_is_git_style_for_ignored_paths() -> None:
    result = CliRunner().invoke(
        main, ["check-ignore", "--format", "text", "skipme/bad.py", "src/kept.py"]
    )

    assert result.exit_code == 0, result.output
    assert result.output == "skipme/bad.py\tconfig:skipme/**\n"
