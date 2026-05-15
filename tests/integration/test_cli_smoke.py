import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruff.cli import main


def test_cli_help_lists_analyse_command():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith("gruff 0.1.0-dev\n\nUsage:\n  command [options] [arguments]")
    assert "Available commands:" in result.output
    for command in (
        "analyse",
        "completion",
        "dashboard",
        "help",
        "list",
        "list-rules",
        "report",
        "summary",
    ):
        assert command in result.output
    for option in ("--silent", "--quiet", "--version", "--ansi", "--no-interaction", "--verbose"):
        assert option in result.output


def test_cli_without_command_prints_php_style_menu():
    result = CliRunner().invoke(main, [])

    assert result.exit_code == 0
    assert result.output.startswith("gruff 0.1.0-dev\n\nUsage:\n")
    assert "Options:" in result.output
    assert "Available commands:" in result.output


def test_cli_root_menu_uses_ansi_colours_when_forced():
    result = CliRunner().invoke(main, ["--ansi"], color=True)

    assert result.exit_code == 0
    assert "\x1b[33mUsage:\x1b" in result.output
    assert "\x1b[32manalyse\x1b" in result.output


def test_cli_command_help_lists_symfony_style_global_options():
    result = CliRunner().invoke(main, ["analyse", "--help"])
    assert result.exit_code == 0
    for option in ("--silent", "--quiet", "--version", "--ansi", "--no-interaction", "--verbose"):
        assert option in result.output
    for option in ("--diff", "--diff-vs", "--baseline", "--generate-baseline"):
        assert option in result.output


def test_cli_list_rules_json_lists_rule_metadata():
    result = CliRunner().invoke(main, ["list-rules", "--format", "json"])
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule = payload["rules"][0]
    assert {
        "id",
        "name",
        "pillar",
        "tier",
        "defaultSeverity",
        "confidence",
        "defaultEnabled",
        "thresholds",
        "options",
        "description",
    } <= set(rule)


def test_cli_report_writes_json_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    output = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        ["report", "--format", "json", "--output", str(output), "--no-config", "src"],
    )

    assert result.exit_code == 0, result.output
    assert result.output == ""
    payload = json.loads(output.read_text())
    assert payload["schemaVersion"] == "gruff.analysis.v1"
    assert payload["run"]["format"] == "json"


def test_cli_summary_json_is_compact_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "src"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "summary" in payload
    assert "topRules" in payload
    assert "topFiles" in payload


def test_cli_quiet_suppresses_success_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--quiet", "--format", "json", "--fail-on", "none", "--no-config", "src"],
    )

    assert result.exit_code == 0
    assert result.output == ""


def test_cli_analyse_emits_schema_versioned_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "short.py").write_text("x = 1\n")
    long_lines = "\n".join(f"x{i} = {i}" for i in range(900)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    assert payload["schemaVersion"] == "gruff.analysis.v1"
    assert payload["tool"]["name"] == "gruff"
    assert payload["summary"]["filesDiscovered"] >= 2
    assert payload["summary"]["filesParsed"] >= 2

    rule_ids = [f["ruleId"] for f in payload["findings"]]
    assert "size.file-length" in rule_ids

    file_length = [f for f in payload["findings"] if f["ruleId"] == "size.file-length"]
    assert len(file_length) == 1
    finding = file_length[0]
    assert len(finding["fingerprint"]) == 16
    assert finding["metadata"]["lines"] >= 900
    assert finding["severity"] == "error"
    assert finding["pillar"] == "size"
    assert finding["tier"] == "v0.1"
    assert finding["confidence"] == "high"


def test_cli_analyse_text_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "text", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
    assert "gruff " in result.output
    assert "Findings" in result.output
    assert "Score" in result.output


def test_cli_analyse_html_format_renders_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "html", "--fail-on", "none", "--no-config", "src"],
    )

    assert result.exit_code == 0, result.output
    assert result.output.startswith("<!DOCTYPE html>")
    assert 'class="paper"' in result.output
    assert "Format: html" not in result.output


def test_cli_analyse_json_display_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    error_lines = "\n".join(f"x{i} = {i}" for i in range(900)) + "\n"
    (src / "warning.py").write_text(warning_lines)
    (src / "error.py").write_text(error_lines)

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--min-severity",
            "error",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["filters"]["active"] is True
    assert payload["run"]["filters"]["minSeverity"] == "error"
    assert {finding["severity"] for finding in payload["findings"]} == {"error"}


def test_cli_applies_configured_secret_preview_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "secrets.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nSTRIPE = 'sk_live_abcdefghijklmnopqrstuvwxyz123456'\n"
    )
    (tmp_path / ".gruff.yaml").write_text(
        "allowlists:\n  secretPreviews:\n    - 'AKIA...MPLE (redacted, 20 chars)'\n"
    )

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "error", "src"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    rule_ids = [finding["ruleId"] for finding in payload["findings"]]
    previews = [
        finding["metadata"].get("preview")
        for finding in payload["findings"]
        if isinstance(finding.get("metadata"), dict)
    ]
    assert "sensitive-data.aws-access-key" not in rule_ids
    assert "sensitive-data.api-key-pattern" in rule_ids
    assert "AKIA...MPLE (redacted, 20 chars)" not in previews


def test_cli_fail_on_error_exits_1_when_errors_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_lines = "\n".join(f"x{i} = {i}" for i in range(900)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "error", "--no-config", "src"],
    )
    assert result.exit_code == 1


def test_cli_fail_on_none_exits_0_even_with_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_lines = "\n".join(f"x{i} = {i}" for i in range(900)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
