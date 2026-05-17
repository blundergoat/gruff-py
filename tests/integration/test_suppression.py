import json
from pathlib import Path

from click.testing import CliRunner

from gruffpy.cli import main


def test_gruff_disable_suppresses_only_matching_rule_on_same_line(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        "import os; eval('payload')  # gruff: disable=waste.unused-import\n"
    )

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-rule",
            "waste.unused-import,security.dangerous-function-call",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [finding["ruleId"] for finding in payload["findings"]] == [
        "security.dangerous-function-call"
    ]


def test_gruff_disable_next_targets_next_physical_line(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        "# gruff: disable-next=security.dangerous-function-call\neval('first')\neval('second')\n"
    )

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-rule",
            "security.dangerous-function-call",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["line"] == 3


def test_gruff_disable_file_is_file_local(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_body = "\n".join(f"x{i} = {i}" for i in range(410)) + "\n"
    (src / "suppressed.py").write_text("# gruff: disable-file=size.file-length\n" + long_body)
    (src / "visible.py").write_text(long_body)

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-rule",
            "size.file-length",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [(finding["file"], finding["ruleId"]) for finding in payload["findings"]] == [
        ("src/visible.py", "size.file-length")
    ]


def test_suppressed_contributors_do_not_create_composite_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(_god_method_source())

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-rule",
            "design.god-method",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []


def _god_method_source() -> str:
    lines = [
        "def god_method(a, b, c, d, e, f):  "
        "# gruff: disable=size.function-length,size.parameter-count",
    ]
    for index in range(11):
        lines.append(f"    if value_{index}:")
        lines.append(f"        result_{index} = {index}")
    lines.extend(f"    padding_{index} = {index}" for index in range(20))
    lines.append("    return a")
    return "\n".join(lines) + "\n"
