import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main
from gruffpy.version import VERSION

_EXPECTED_ROOT_COMMANDS = (
    "analyse",
    "completion",
    "dashboard",
    "help",
    "list",
    "list-rules",
    "report",
    "summary",
)
_HIDDEN_ROOT_COMMANDS = ("metric-calibration",)
_EXPECTED_GLOBAL_OPTIONS = (
    "--silent",
    "--quiet",
    "--version",
    "--ansi",
    "--no-interaction",
    "--verbose",
)


def test_cli_help_lists_analyse_command():
    """Guard the root help contract across visible commands and global options."""
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith(
        f"gruff-py {VERSION}\n\nUsage:\n  command [options] [arguments]"
    )
    assert "Available commands:" in result.output
    classification = {
        "missing_commands": [c for c in _EXPECTED_ROOT_COMMANDS if c not in result.output],
        "leaked_commands": [c for c in _HIDDEN_ROOT_COMMANDS if c in result.output],
        "missing_options": [o for o in _EXPECTED_GLOBAL_OPTIONS if o not in result.output],
    }
    assert classification == {"missing_commands": [], "leaked_commands": [], "missing_options": []}


def test_cli_without_command_prints_php_style_menu():
    result = CliRunner().invoke(main, [])

    assert result.exit_code == 0
    assert result.output.startswith(f"gruff-py {VERSION}\n\nUsage:\n")
    assert "Options:" in result.output
    assert "Available commands:" in result.output


def test_cli_root_menu_uses_ansi_colours_when_forced():
    result = CliRunner().invoke(main, ["--ansi"], color=True)

    assert result.exit_code == 0
    assert "\x1b[33mUsage:\x1b" in result.output
    assert "\x1b[32manalyse\x1b" in result.output


_EXPECTED_ANALYSE_LOCAL_OPTIONS = ("--diff", "--diff-vs", "--baseline", "--generate-baseline")


def test_cli_command_help_lists_symfony_style_global_options():
    result = CliRunner().invoke(main, ["analyse", "--help"])
    assert result.exit_code == 0
    missing_global = [o for o in _EXPECTED_GLOBAL_OPTIONS if o not in result.output]
    missing_local = [o for o in _EXPECTED_ANALYSE_LOCAL_OPTIONS if o not in result.output]
    assert missing_global == [], f"missing global options in analyse --help: {missing_global}"
    assert missing_local == [], f"missing local options in analyse --help: {missing_local}"
    assert "sarif" in result.output


_REQUIRED_RULE_PAYLOAD_KEYS = frozenset(
    {
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
        "documentation",
    }
)
_REQUIRED_RULE_DOCUMENTATION_KEYS = frozenset({"rationale", "fixGuidance", "confidenceRationale"})


def test_cli_list_rules_json_lists_rule_metadata():
    result = CliRunner().invoke(main, ["list-rules", "--format", "json"])
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule = payload["rules"][0]
    assert set(rule) >= _REQUIRED_RULE_PAYLOAD_KEYS
    assert set(rule["documentation"]) >= _REQUIRED_RULE_DOCUMENTATION_KEYS


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
    assert payload["schemaVersion"] == "gruff-py.analysis.v1"
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
    assert payload["summary"]["paths"] == ["src"]
    assert isinstance(payload["summary"]["elapsedSeconds"], int | float)
    assert payload["summary"]["elapsedSeconds"] >= 0


def test_cli_summary_text_includes_path_and_elapsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    assert "Path: src" in result.output
    assert "Elapsed:" in result.output


def test_cli_metric_calibration_json_is_developer_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        "def sample(value):\n"
        "    if value > 0 and value < 10:\n"
        "        return value + 1\n"
        "    return value - 1\n"
    )

    result = CliRunner().invoke(
        main,
        ["metric-calibration", "--format", "json", "--no-config", "--top", "1", "src"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schemaVersion"] == "gruff-py.metric-calibration.v1"
    assert payload["run"]["functions"] == 1
    assert {metric["name"] for metric in payload["metrics"]} == {
        "cyclomatic",
        "npath",
        "halsteadVolume",
        "maintainabilityIndex",
    }
    assert payload["top"]["cyclomatic"][0]["symbol"] == "sample"


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


_LONG_FIXTURE_LINE_COUNT = 1001
_FINGERPRINT_HEX_LENGTH = 16


def _analyse_short_and_long_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "short.py").write_text("x = 1\n")
    long_lines = "\n".join(f"x{i} = {i}" for i in range(_LONG_FIXTURE_LINE_COUNT)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_cli_analyse_emits_schema_version_and_tool_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["schemaVersion"] == "gruff-py.analysis.v1"
    assert payload["tool"]["name"] == "gruff-py"


def test_cli_analyse_summary_counts_at_least_two_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["summary"]["filesDiscovered"] >= 2
    assert payload["summary"]["filesParsed"] >= 2


def test_cli_analyse_emits_file_length_finding_with_full_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    file_length = [f for f in payload["findings"] if f["ruleId"] == "size.file-length"]
    assert len(file_length) == 1
    finding = file_length[0]
    assert len(finding["fingerprint"]) == _FINGERPRINT_HEX_LENGTH
    assert finding["metadata"]["lines"] >= _LONG_FIXTURE_LINE_COUNT
    assert (finding["severity"], finding["pillar"], finding["tier"], finding["confidence"]) == (
        "error",
        "size",
        "v0.1",
        "high",
    )


def test_cli_analyse_sarif_format_is_parseable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "long.py").write_text("\n".join(f"x{i} = {i}" for i in range(1001)) + "\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "sarif", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "gruff-py"
    assert payload["runs"][0]["results"][0]["partialFingerprints"]["gruffFingerprint"]


def _sarif_fixture_payload() -> dict:
    fixture = Path("tests/fixtures/complexity")
    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "sarif",
            "--fail-on",
            "none",
            "--no-config",
            str(fixture),
        ],
    )
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_cli_analyse_sarif_fixture_payload_advertises_schema_versions() -> None:
    payload = _sarif_fixture_payload()
    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "gruff-py"
    assert run["properties"]["gruffSchemaVersion"] == "gruff-py.analysis.v1"


def test_cli_analyse_sarif_fixture_driver_rules_are_sorted_and_nonempty() -> None:
    run = _sarif_fixture_payload()["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)
    assert len(run["results"]) > 0


def test_cli_analyse_sarif_fixture_every_result_has_fingerprint_and_matching_rule_index() -> None:
    run = _sarif_fixture_payload()["runs"][0]
    driver_rules = run["tool"]["driver"]["rules"]
    missing_fp = [r for r in run["results"] if not r["partialFingerprints"]["gruffFingerprint"]]
    mismatched_rule_index = [
        r for r in run["results"] if driver_rules[r["ruleIndex"]]["id"] != r["ruleId"]
    ]
    assert missing_fp == [], f"results missing gruffFingerprint: {missing_fp}"
    assert mismatched_rule_index == [], f"ruleIndex/ruleId mismatches: {mismatched_rule_index}"


def test_cli_analyse_sarif_fixture_artifact_uris_are_normalised() -> None:
    run = _sarif_fixture_payload()["runs"][0]
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    ]
    bad = [uri for uri in uris if uri.startswith("./") or "\\" in uri]
    assert bad == [], f"un-normalised artifact URIs: {bad}"


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
    assert "gruff-py " in result.output
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
    error_lines = "\n".join(f"x{i} = {i}" for i in range(1001)) + "\n"
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


def test_cli_analyse_accepts_comma_separated_pillar_filters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "long.py").write_text("\n".join(f"x{i} = {i}" for i in range(1001)) + "\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--include-pillar",
            "size,documentation",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["filters"]["includePillars"] == ["size", "documentation"]


def test_cli_applies_configured_secret_preview_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    aws_key = "AKIA" + "1234567890ABCDEF"
    aws_preview = "AKIA...CDEF (redacted, 20 chars)"
    stripe_key = "sk_live_" + "abcdefghijklmno" + "pqrstuvwxyz123456"
    (src / "secrets.py").write_text(f"AWS_KEY = '{aws_key}'\nSTRIPE = '{stripe_key}'\n")
    (tmp_path / ".gruff-py.yaml").write_text(
        f"allowlists:\n  secretPreviews:\n    - '{aws_preview}'\n"
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
    assert aws_preview not in previews


def test_cli_fail_on_error_exits_1_when_errors_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_lines = "\n".join(f"x{i} = {i}" for i in range(1001)) + "\n"
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
    long_lines = "\n".join(f"x{i} = {i}" for i in range(1001)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
