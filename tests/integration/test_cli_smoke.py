# gruff: disable-file=size.file-length -- end-to-end CLI smoke covers every subcommand.
# gruff: disable-file=test-quality.eager-test -- smoke tests assert many invariants per call.
# gruff: disable-file=test-quality.loop-in-test -- loops enumerate output rows, not test cases.
# gruff: disable-file=test-quality.magic-number-assertion -- column positions are the contract.
# gruff: disable-file=test-quality.conditional-logic -- branches mirror the --format axis.
# gruff: disable-file=test-quality.loop-assertion-without-message -- row ruleId self-describes.
# gruff: disable-file=docs.complex-branch-rationale -- branches mirror the --format axis.
"""Exercise complete CLI journeys from user-entered options to visible output.

The smoke suite protects every command's parsing, diagnostics, and report shape.
Dashboard launch tests replace the blocking HTTP server while preserving the
startup messages and validation a terminal user sees.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
import yaml
from click.testing import CliRunner

import gruffpy.cli as cli_module
from gruffpy.cli import _normalise_optional_diff_args, main
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import VERSION

_EXPECTED_ROOT_COMMANDS = (
    "analyse",
    "check-ignore",
    "completion",
    "dashboard",
    "help",
    "hook",
    "init",
    "list",
    "list-rules",
    "migrate-config",
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
_GIT = shutil.which("git")
_DASHBOARD_COMPAT_HELP_PHRASE = "accepted for cross-port compatibility; not implemented in gruff-py"


def test_cli_help_lists_analyse_command():
    """Guard the root help contract across visible commands and global options."""
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith(f"gruff-py {VERSION}\n\nUsage:\n  command [options] [arguments]")
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


def test_cli_menu_keeps_a_gutter_after_the_longest_command_name():
    result = CliRunner().invoke(main, ["--no-ansi"])

    assert result.exit_code == 0
    assert "migrate-configRewrite" not in result.output
    assert "migrate-config  Rewrite legacy config keys" in result.output
    assert "check-ignore    Report whether gruff would ignore" in result.output


def test_optional_diff_args_resolves_sys_argv_for_real_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Console-script / python -m calls reach CliGroup.main with args=None.

    # Click would then read sys.argv itself, skipping normalisation. The helper must resolve
    # sys.argv so a bare --diff still becomes --diff=working-tree outside CliRunner.
    monkeypatch.setattr(sys, "argv", ["gruff-py", "analyse", "--diff"])
    assert _normalise_optional_diff_args(None) == ["analyse", "--diff=working-tree"]

    monkeypatch.setattr(sys, "argv", ["gruff-py", "analyse", "--diff", "main"])
    assert _normalise_optional_diff_args(None) == ["analyse", "--diff", "main"]


_EXPECTED_ANALYSE_LOCAL_OPTIONS = (
    "--diff",
    "--diff-vs",
    "--since",
    "--changed-ranges",
    "--changed-scope",
    "--baseline-path",
    "--generate-baseline",
    "--generate-baseline-path",
    "--deep-scan-budget",
)


def test_cli_command_help_lists_symfony_style_global_options():
    """Guard the analyse --help contract: globals, locals, formats, no docstring leakage."""
    result = CliRunner().invoke(main, ["analyse", "--help"])
    classification = {
        "exit_code": result.exit_code,
        "missing_global": [o for o in _EXPECTED_GLOBAL_OPTIONS if o not in result.output],
        "missing_local": [o for o in _EXPECTED_ANALYSE_LOCAL_OPTIONS if o not in result.output],
        "missing_sarif": "sarif" not in result.output,
        "leaked_docstring_sections": [s for s in ("Args:", "Raises:") if s in result.output],
    }
    assert classification == {
        "exit_code": 0,
        "missing_global": [],
        "missing_local": [],
        "missing_sarif": False,
        "leaked_docstring_sections": [],
    }


def test_analyse_help_explains_fail_on_diagnostic_boundary() -> None:
    """Keep parse failures outside the findings-only severity gate."""
    result = CliRunner().invoke(main, ["analyse", "--help"])
    searchable_help = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert "Gates findings only; parse errors exit 2 even with --fail-on none." in searchable_help


def test_cli_dashboard_help_labels_accepted_compatibility_options_honestly() -> None:
    """Tell dashboard users that accepted family flags have no Python behavior."""
    result = CliRunner().invoke(main, ["dashboard", "--help"])
    searchable_help = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert f"--diff Diff-only dashboard scans: {_DASHBOARD_COMPAT_HELP_PHRASE}." in searchable_help
    assert f"--scan-timeout INTEGER Dashboard scan timeouts: {_DASHBOARD_COMPAT_HELP_PHRASE}." in searchable_help
    assert result.output.count(_DASHBOARD_COMPAT_HELP_PHRASE) == 2


def test_analyse_changed_ranges_returns_only_changed_method_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def old_bad():\n    eval('old')\n\n\ndef new_bad():\n    eval('new')\n")

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
            "docs.missing-function-docstring",
            "--changed-ranges",
            "6-6",
            "src/sample.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [finding["symbol"] for finding in payload["findings"]] == ["new_bad"]
    assert payload["summary"]["suppressedFindings"] >= 1


def test_analyse_changed_region_fail_on_warning_gates_retained_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('"""Module."""\n\n\ndef changed():\n    return 1\n')

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "warning",
            "--no-config",
            "--no-baseline",
            "--changed-ranges",
            "5-5",
            "src/sample.py",
        ],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 1, result.output
    assert [finding["symbol"] for finding in payload["findings"]] == ["changed"]
    assert payload["summary"]["exitCode"] == 1
    assert payload["diff"]["changedFiles"] == ["src/sample.py"]

    full_scan = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "warning",
            "--no-config",
            "--no-baseline",
            "src/sample.py",
        ],
    )

    full_payload = json.loads(full_scan.output)
    assert full_scan.exit_code == 1, full_scan.output
    assert "diff" not in full_payload
    assert "changed" in {finding.get("symbol") for finding in full_payload["findings"]}


def test_analyse_changed_region_suppresses_out_of_scope_debt_before_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        '"""Module."""\n\n\n'
        "def changed():\n"
        '    """Return the changed-path value without touching legacy debt."""\n'
        "    return 1\n\n\n"
        "def old_bad():\n"
        "    return 2\n"
    )

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "warning",
            "--no-config",
            "--no-baseline",
            "--changed-ranges",
            "6-6",
            "src/sample.py",
        ],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 0, result.output
    assert payload["findings"] == []
    assert payload["summary"]["suppressedFindings"] >= 1
    assert payload["diff"]["filteredFindings"] == payload["summary"]["suppressedFindings"]


def test_analyse_changed_scope_symbol_anchors_file_length_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "README.md").write_text("# Test project\n")
    src = tmp_path / "src"
    src.mkdir()
    # The module docstring is free under substantive counting, so 1008 route entries keep the
    # file at exactly 1010 substantive lines for the metadata pin below.
    (src / "sample.py").write_text(
        '"""Utilities for changed-region file length regression coverage."""\n'
        + "ROUTES = [\n"
        + "".join(f'    "route-{index}",\n' for index in range(1008))
        + "]\n"
    )
    base = ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline"]

    far = CliRunner().invoke(
        main,
        [*base, "--changed-ranges", "500-500", "--changed-scope", "symbol", "src/sample.py"],
    )
    anchor = CliRunner().invoke(
        main,
        [*base, "--changed-ranges", "1-1", "--changed-scope", "symbol", "src/sample.py"],
    )
    full = CliRunner().invoke(main, [*base, "src/sample.py"])

    assert far.exit_code == 0, far.output
    assert anchor.exit_code == 0, anchor.output
    assert full.exit_code == 0, full.output
    far_payload = json.loads(far.output)
    anchor_payload = json.loads(anchor.output)
    full_payload = json.loads(full.output)

    assert [finding["ruleId"] for finding in far_payload["findings"]] == []
    assert far_payload["summary"]["suppressedFindings"] >= 1
    assert far_payload["diff"]["filteredFindings"] == far_payload["summary"]["suppressedFindings"]

    anchor_file_length = [finding for finding in anchor_payload["findings"] if finding["ruleId"] == "size.file-length"]
    full_file_length = [finding for finding in full_payload["findings"] if finding["ruleId"] == "size.file-length"]
    assert len(anchor_file_length) == 1
    assert len(full_file_length) == 1
    assert anchor_file_length[0]["line"] == 1
    assert anchor_file_length[0]["metadata"]["lines"] == 1010
    assert anchor_file_length[0]["metadata"]["threshold"] == 1000
    assert "suppressedFindings" not in full_payload["summary"]
    assert "diff" not in full_payload


def test_analyse_changed_scope_symbol_and_hunk_gate_different_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        '"""Module."""\n'
        "import subprocess\n\n\n"
        "def changed():\n"
        '    """Run legacy diagnostics through the shell for compatibility."""\n'
        '    command = "ls"\n'
        "    subprocess.run(command, shell=True)\n"
        "    return 1\n"
    )

    common_args = [
        "analyse",
        "--format",
        "json",
        "--fail-on",
        "warning",
        "--no-config",
        "--no-baseline",
        "--changed-ranges",
        "9-9",
        "src/sample.py",
    ]

    symbol = CliRunner().invoke(main, [*common_args, "--changed-scope", "symbol"])
    hunk = CliRunner().invoke(main, [*common_args, "--changed-scope", "hunk"])

    symbol_payload = json.loads(symbol.output)
    hunk_payload = json.loads(hunk.output)
    assert symbol.exit_code == 1, symbol.output
    assert [finding["ruleId"] for finding in symbol_payload["findings"]] == ["security.shell-injection"]
    assert hunk.exit_code == 0, hunk.output
    assert hunk_payload["findings"] == []
    assert hunk_payload["summary"]["suppressedFindings"] >= 1


_CHANGED_SCOPE_BASE = ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline"]
_BETA_DEFINITION_LINE = 5


def _three_symbol_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a module whose alpha, beta, and gamma functions each carry documentation debt.

    Definition lines are alpha:1, beta:5, gamma:9, so a change on line 6 sits inside beta's body.

    Args:
        tmp_path: Directory used as the project root.
        monkeypatch: Fixture used to make that directory the working directory.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n\n\ndef gamma():\n    return 3\n")


def _scan(*arguments: str) -> dict:
    """Run one analyse invocation and return its parsed report.

    Args:
        arguments: Extra arguments appended to the shared changed-scope base command.

    Returns:
        The parsed JSON report.
    """
    result = CliRunner().invoke(main, [*_CHANGED_SCOPE_BASE, *arguments])
    assert result.exit_code == 0, result.output
    payload: dict = json.loads(result.output)
    return payload


def test_analyse_full_scan_carries_no_changed_region_counters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run the user did not scope reports every symbol and no diff accounting.

    Args:
        tmp_path: Project root for this run.
        monkeypatch: Fixture used to enter that root.
    """
    _three_symbol_project(tmp_path, monkeypatch)

    full_payload = _scan("src/sample.py")

    assert {"alpha", "beta", "gamma"} <= {finding.get("symbol") for finding in full_payload["findings"]}
    assert "suppressedFindings" not in full_payload["summary"]
    assert "diff" not in full_payload


def test_analyse_changed_scope_symbol_surfaces_only_the_edited_symbol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Symbol scope widens a line edit to its whole declaration and leaves siblings alone.

    Args:
        tmp_path: Project root for this run.
        monkeypatch: Fixture used to enter that root.
    """
    _three_symbol_project(tmp_path, monkeypatch)

    scoped_payload = _scan("--changed-ranges", "6-6", "--changed-scope", "symbol", "src/sample.py")

    surfaced_symbols = {finding.get("symbol") for finding in scoped_payload["findings"]}
    assert "beta" in surfaced_symbols
    assert surfaced_symbols.isdisjoint({"alpha", "gamma"})
    assert any(finding["line"] == _BETA_DEFINITION_LINE for finding in scoped_payload["findings"])


def test_analyse_changed_scope_symbol_accounts_for_every_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No finding is dropped silently: surfaced plus suppressed accounts for the full-scan total.

    The totals are read from the runs rather than hard-coded, so the check survives catalogue growth.

    Args:
        tmp_path: Project root for both runs.
        monkeypatch: Fixture used to enter that root.
    """
    _three_symbol_project(tmp_path, monkeypatch)
    total = len(_scan("src/sample.py")["findings"])

    scoped_payload = _scan("--changed-ranges", "6-6", "--changed-scope", "symbol", "src/sample.py")

    suppressed = scoped_payload["summary"]["suppressedFindings"]
    assert len(scoped_payload["findings"]) + suppressed == total
    assert suppressed >= 1
    assert scoped_payload["diff"]["filteredFindings"] == suppressed


def test_analyse_agent_command_ignores_default_baseline_when_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('"""Module."""\n\n\ndef changed():\n    return 1\n')
    generated = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--generate-baseline",
            "src/sample.py",
        ],
    )
    assert generated.exit_code == 0, generated.output
    assert (tmp_path / "gruff-baseline.json").exists()

    common_args = [
        "analyse",
        "--format",
        "json",
        "--fail-on",
        "warning",
        "--no-config",
        "--changed-ranges",
        "5-5",
        "src/sample.py",
    ]
    auto_baselined = CliRunner().invoke(main, common_args)
    agent_scoped = CliRunner().invoke(main, [*common_args, "--no-baseline"])

    auto_payload = json.loads(auto_baselined.output)
    agent_payload = json.loads(agent_scoped.output)
    assert auto_baselined.exit_code == 0, auto_baselined.output
    assert auto_payload["findings"] == []
    assert auto_payload["baseline"]["source"] == "default"
    assert auto_payload["baseline"]["suppressedFindings"] >= 1
    assert agent_scoped.exit_code == 1, agent_scoped.output
    assert [finding["symbol"] for finding in agent_payload["findings"]] == ["changed"]
    assert "baseline" not in agent_payload


def test_analyse_diff_stdin_filters_to_changed_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "old.py").write_text("def old_bad():\n    eval('old')\n")
    (src / "new.py").write_text("def new_bad():\n    eval('new')\n")
    patch = "diff --git a/src/new.py b/src/new.py\n--- a/src/new.py\n+++ b/src/new.py\n@@ -2,0 +2,1 @@\n+    eval('new')\n"

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
            "docs.missing-function-docstring",
            "--diff",
            "-",
            "src",
        ],
        input=patch,
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert {finding["file"] for finding in payload["findings"]} == {"src/new.py"}
    assert payload["diff"]["mode"] == "stdin"


@pytest.mark.skipif(_GIT is None, reason="git is unavailable")
@pytest.mark.parametrize(
    ("diff_args", "should_stage", "expected_source"),
    [
        (("--diff=working-tree",), False, "working-tree"),
        (("--diff=staged",), True, "staged"),
        (("--since", "HEAD"), False, "HEAD"),
    ],
    ids=("working-tree", "staged", "since-head"),
)
def test_analyse_git_changed_region_modes_gate_retained_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    diff_args: tuple[str, ...],
    should_stage: bool,
    expected_source: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    target = src / "sample.py"
    target.write_text('"""Module."""\n\n\ndef changed():\n    """Return one."""\n    return 1\n')
    _init_git_history(tmp_path, "src/sample.py")
    target.write_text('"""Module."""\n\n\ndef changed():\n    return 2\n')
    if should_stage:
        _run_git(tmp_path, "add", "src/sample.py")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "warning",
            "--no-config",
            "--no-baseline",
            *diff_args,
            "src/sample.py",
        ],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 1, result.output
    assert [finding["symbol"] for finding in payload["findings"]] == ["changed"]
    assert payload["diff"]["mode"] == expected_source
    assert payload["diff"]["changedFiles"] == ["src/sample.py"]


def _run_git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert _GIT is not None
    return subprocess.run(
        [_GIT, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_git_history(cwd: Path, *paths: str) -> None:
    _run_git(cwd, "init", "-q")
    _run_git(cwd, "add", *paths)
    tree = _run_git(cwd, "write-tree").stdout.strip()
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "gruff-py tests",
        "GIT_AUTHOR_EMAIL": "gruff-py-tests",
        "GIT_COMMITTER_NAME": "gruff-py tests",
        "GIT_COMMITTER_EMAIL": "gruff-py-tests",
    }
    assert _GIT is not None
    commit = subprocess.run(
        [_GIT, "commit-tree", tree, "-m", "initial"],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()
    _run_git(cwd, "update-ref", "HEAD", commit)


_REQUIRED_RULE_PAYLOAD_KEYS = frozenset(
    {
        "id",
        "name",
        "pillar",
        "tier",
        "defaultSeverity",
        "confidence",
        "defaultEnabled",
        "options",
        "description",
        "documentation",
    }
)
_REQUIRED_RULE_DOCUMENTATION_KEYS = frozenset({"rationale", "fixGuidance", "confidenceRationale"})


def _list_rules_payload() -> dict:
    """Run ``list-rules --format json`` and return its parsed catalogue.

    Returns:
        The parsed catalogue payload.
    """
    result = CliRunner().invoke(main, ["list-rules", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload: dict = json.loads(result.output)
    return payload


def test_cli_list_rules_json_lists_rule_metadata():
    rule = _list_rules_payload()["rules"][0]

    assert set(rule) >= _REQUIRED_RULE_PAYLOAD_KEYS
    assert set(rule["documentation"]) >= _REQUIRED_RULE_DOCUMENTATION_KEYS


def test_cli_list_rules_json_publishes_heuristic_false_positive_shapes():
    payload = _list_rules_payload()

    heuristic_rule = next(candidate for candidate in payload["rules"] if candidate["id"] == "complexity.halstead-volume")
    assert heuristic_rule["falsePositiveShapes"]
    assert "falsePositiveShapes" not in heuristic_rule["documentation"]


def test_cli_list_rules_accepts_text_alias():
    result = CliRunner().invoke(main, ["list-rules", "--format", "text"])

    assert result.exit_code == 0, result.output
    assert "Rule" in result.output
    assert "Pillar" in result.output


def test_cli_list_rules_default_remains_unchanged_by_explain_mode():
    result = CliRunner().invoke(main, ["list-rules"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Rule")
    assert "Pillar" in result.output
    # the explain header should NOT appear in the catalogue view
    assert "Rationale:" not in result.output
    assert "Escape hatches:" not in result.output


def test_cli_list_rules_explain_text_renders_full_detail_view():
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variable"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Rule: naming.short-variable")
    assert "Severity:  advisory (default)" in result.output
    assert "Rationale:" in result.output
    assert "Default options:" in result.output
    assert "acceptedShortNames" in result.output
    assert "Escape hatches:" in result.output
    assert "rules.naming.short-variable.enabled" in result.output
    assert "Common false-positive shapes:" in result.output
    assert "Related rules:" in result.output
    assert "naming.abbreviation" in result.output


def test_cli_list_rules_explain_table_format_coerces_to_text():
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variable", "--format", "table"])

    assert result.exit_code == 0, result.output
    # table format would render header rows; detail view starts with `Rule:`
    assert result.output.startswith("Rule: naming.short-variable")


def test_cli_list_rules_explain_json_emits_structured_payload():
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variable", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["id"] == "naming.short-variable"
    assert payload["pillar"] == "naming"
    assert payload["defaultSeverity"] == "advisory"
    assert payload["relatedRules"] == ["naming.abbreviation", "naming.identifier-quality"]
    assert "optionDescriptions" in payload["documentation"]
    assert "acceptedShortNames" in payload["documentation"]["optionDescriptions"]
    assert payload["documentation"]["falsePositiveShapes"]


def test_cli_list_rules_explain_unknown_id_exits_one_with_suggestion():
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variabel"])

    assert result.exit_code == 1
    assert "Unknown rule: naming.short-variabel" in result.stderr
    assert "Did you mean: naming.short-variable" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_list_rules_explain_rule_with_no_options_omits_options_section():
    # naming.abbreviation reads allowlists.acceptedAbbreviations (global), no per-rule options.
    result = CliRunner().invoke(main, ["list-rules", "naming.abbreviation"])

    assert result.exit_code == 0, result.output
    assert "Default options:" not in result.output
    # but FP shapes and Related rules ALWAYS appear
    assert "Common false-positive shapes:" in result.output
    assert "Related rules:" in result.output


def test_cli_list_rules_explain_rule_with_no_related_rules_shows_none_marker():
    # docs.todo-density is not a key in RELATED_RULES, so its "Related rules:"
    # block should render the "(none)" marker.
    result = CliRunner().invoke(main, ["list-rules", "docs.todo-density"])

    assert result.exit_code == 0, result.output
    related_block = result.output.split("Related rules:")[-1]
    assert "(none)" in related_block


def test_cli_init_writes_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a loadable starter config when the user's project has none.

    Args:
        tmp_path: Empty project that receives the generated config.
        monkeypatch: Fixture that makes the empty project the CLI working directory.
    """
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["init"])

    target = tmp_path / ".gruff-py.yaml"
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert result.output.startswith(f"Wrote {target}\n")
    assert "gruff-py analyse . --generate-baseline" in result.output


def test_cli_init_help_describes_canonical_regeneration_boundary() -> None:
    """Tell users force preserves settings but may rewrite comments and layout."""
    result = CliRunner().invoke(main, ["init", "--help"])
    user_visible_help = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert "all supported settings" in user_visible_help
    assert "comments and formatting may change" in user_visible_help


def test_cli_init_default_config_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(main, ["init"])

    config_text = (tmp_path / ".gruff-py.yaml").read_text()
    assert config_text.startswith("# gruff-py configuration - .gruff-py.yaml\n")
    assert "Built-in ignores and .gitignore already apply" in config_text
    assert "- .agents/" in config_text
    assert "- tests/fixtures/**" in config_text


def test_cli_init_refuses_to_overwrite_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("# do not clobber\n")

    result = CliRunner().invoke(main, ["init"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert existing.read_text() == "# do not clobber\n"


def test_cli_analyse_does_not_prompt_when_stdin_lacks_tty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "src"],
    )

    assert result.exit_code == 0, result.output
    assert "Generate a default config" not in result.output
    assert not (tmp_path / ".gruff-py.yaml").exists()


def _stub_dashboard_server(
    monkeypatch: pytest.MonkeyPatch,
    dashboard_host: str,
) -> Mock:
    """Replace the blocking HTTP server while preserving the user's launch flow.

    Args:
        monkeypatch: Fixture that redirects dashboard startup to the test double.
        dashboard_host: Non-empty host shown back to the user in the startup URL.

    Returns:
        Server-factory mock used to prove whether startup was attempted; never None.
    """
    dashboard_server = Mock()
    dashboard_server.server_address = (dashboard_host, 8765)
    dashboard_server_factory = Mock(return_value=dashboard_server)
    monkeypatch.setattr(cli_module, "_dashboard_server", dashboard_server_factory)
    return dashboard_server_factory


@pytest.mark.parametrize(
    "compatibility_arguments",
    (("--diff",), ("--scan-timeout", "5")),
    ids=("diff", "scan-timeout"),
)
def test_cli_dashboard_compatibility_options_still_reach_server_startup(
    monkeypatch: pytest.MonkeyPatch,
    compatibility_arguments: tuple[str, ...],
) -> None:
    """Keep family-compatible flags parseable without claiming they affect scans.

    Args:
        monkeypatch: Fixture that prevents a real dashboard server from blocking.
        compatibility_arguments: Non-empty dashboard flag invocation under test.
    """
    dashboard_server_factory = _stub_dashboard_server(monkeypatch, "127.0.0.1")

    result = CliRunner().invoke(
        main,
        ["dashboard", "--no-config", *compatibility_arguments],
    )

    assert result.exit_code == 0, result.output
    dashboard_server_factory.assert_called_once()


@pytest.mark.parametrize("remote_dashboard_host", ("0.0.0.0", "192.0.2.1"))
def test_cli_dashboard_refuses_remote_host_without_acknowledgment(
    monkeypatch: pytest.MonkeyPatch,
    remote_dashboard_host: str,
) -> None:
    """Stop users from exposing an unauthenticated dashboard accidentally.

    Args:
        monkeypatch: Fixture that proves refusal happens before server startup.
        remote_dashboard_host: Non-loopback host the user attempted to expose.
    """
    dashboard_server_factory = _stub_dashboard_server(monkeypatch, remote_dashboard_host)

    result = CliRunner().invoke(
        main,
        ["dashboard", "--no-config", "--host", remote_dashboard_host],
    )

    assert result.exit_code == 1, result.output
    assert (
        "Refusing to bind the unauthenticated dashboard to non-loopback host "
        f'"{remote_dashboard_host}". Pass --allow-public to acknowledge that remote '
        "users can scan any directory readable by this process."
    ) in result.output
    dashboard_server_factory.assert_not_called()


@pytest.mark.parametrize("remote_dashboard_host", ("0.0.0.0", "192.0.2.1"))
def test_cli_dashboard_warns_after_remote_host_acknowledgment(
    monkeypatch: pytest.MonkeyPatch,
    remote_dashboard_host: str,
) -> None:
    """Warn users who intentionally acknowledge remote dashboard exposure.

    Args:
        monkeypatch: Fixture that lets the acknowledged launch finish immediately.
        remote_dashboard_host: Non-loopback host accepted after acknowledgment.
    """
    dashboard_server_factory = _stub_dashboard_server(monkeypatch, remote_dashboard_host)

    result = CliRunner().invoke(
        main,
        [
            "dashboard",
            "--no-config",
            "--host",
            remote_dashboard_host,
            "--allow-public",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (
        f"WARNING: binding dashboard to non-loopback host {remote_dashboard_host}; remote "
        "users can access the unauthenticated dashboard and scan any directory readable "
        "by this process."
    ) in result.output
    dashboard_server_factory.assert_called_once()


@pytest.mark.parametrize(
    "loopback_dashboard_host",
    ("127.0.0.1", "localhost", "::1", "127.0.0.2"),
    ids=("ipv4", "hostname", "ipv6", "ipv4-range"),
)
def test_cli_dashboard_keeps_loopback_hosts_available_without_acknowledgment(
    monkeypatch: pytest.MonkeyPatch,
    loopback_dashboard_host: str,
) -> None:
    """Keep local dashboard launches unchanged and free of exposure warnings.

    Args:
        monkeypatch: Fixture that lets each local launch finish immediately.
        loopback_dashboard_host: Local-only host that needs no acknowledgment.
    """
    dashboard_server_factory = _stub_dashboard_server(monkeypatch, loopback_dashboard_host)

    result = CliRunner().invoke(
        main,
        ["dashboard", "--no-config", "--host", loopback_dashboard_host],
    )

    assert result.exit_code == 0, result.output
    assert "WARNING: binding dashboard to non-loopback host" not in result.output
    dashboard_server_factory.assert_called_once()


def test_cli_dashboard_rejects_invalid_project_root_before_prompting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure a bad ``--project`` surfaces as a directory error before any prompt.

    Args:
        tmp_path: Working directory for the invocation.
        monkeypatch: Fixture used to chdir into ``tmp_path``.
    """
    monkeypatch.chdir(tmp_path)
    bogus = tmp_path / "does-not-exist"

    result = CliRunner().invoke(main, ["dashboard", "--project", str(bogus)])

    assert result.exit_code != 0
    assert "Project root is not a directory" in result.output
    assert "Unable to write" not in result.output
    assert not (bogus / ".gruff-py.yaml").exists()


def test_cli_dashboard_rejects_invalid_port_before_prompting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an invalid port before config initialization or server startup.

    Args:
        monkeypatch: Fixture that records both side effects after option parsing.
    """
    config_prompt = Mock()
    monkeypatch.setattr(cli_module, "_maybe_prompt_to_init_config", config_prompt)
    dashboard_server_factory = _stub_dashboard_server(monkeypatch, "127.0.0.1")

    result = CliRunner().invoke(main, ["dashboard", "--port", "65536"])

    assert result.exit_code == 1, result.output
    assert "--port must be between 0 and 65535." in result.output
    config_prompt.assert_not_called()
    dashboard_server_factory.assert_not_called()


def test_cli_init_force_regenerates_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Canonically rewrite valid target YAML without changing loaded settings.

    Args:
        tmp_path: Project containing the valid target to regenerate.
        monkeypatch: Fixture that makes the target's project the working directory.
    """
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("# comments may be canonicalised\nschemaVersion: gruff-py.config.v0.1\nminimumPythonVersion: '3.12'\n")
    defaults = AnalysisConfig.from_registry(RuleRegistry.defaults())
    before, _ = ConfigLoader(tmp_path, defaults, strict=True).load()

    result = CliRunner().invoke(main, ["init", "--force"])

    after, _ = ConfigLoader(tmp_path, defaults, strict=True).load()
    assert result.exit_code == 0, result.output
    assert existing.read_text().startswith("# gruff-py configuration - .gruff-py.yaml\n")
    assert after == before


def test_cli_init_force_preserves_existing_ignore_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the user's exact ignore semantics without adding starter entries.

    Args:
        tmp_path: Project containing user-selected ignore patterns.
        monkeypatch: Fixture that makes the configured project the working directory.
    """
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - generated/**\n    - .codex/\n")

    result = CliRunner().invoke(main, ["init", "--force"])

    document = yaml.safe_load(existing.read_text())
    assert result.exit_code == 0, result.output
    assert document["paths"]["ignore"] == ["generated/**", ".codex/"]


def test_cli_init_force_refuses_to_wipe_malformed_ignore_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed when existing target YAML cannot be loaded strictly.

    Args:
        tmp_path: Project containing a malformed user ignore value.
        monkeypatch: Fixture that makes the malformed project the working directory.
    """
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    original = "schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore: generated/**\n"
    existing.write_text(original)

    result = CliRunner().invoke(main, ["init", "--force"])

    assert result.exit_code != 0
    assert "[tool.gruff-py.paths].ignore must be a list of strings" in result.output
    assert existing.read_text() == original


@pytest.mark.parametrize(
    ("source_name", "source_text", "expected_guidance"),
    (
        (
            ".gruff.yaml",
            "schemaVersion: gruff-py.config.v0.1\n",
            "migrate-config",
        ),
        (
            "pyproject.toml",
            '[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n',
            "TOML",
        ),
        (
            "pyproject.toml",
            '[tool.gruff]\nschemaVersion = "gruff-py.config.v0.1"\n',
            "TOML",
        ),
    ),
    ids=("legacy-yaml", "modern-toml", "legacy-toml"),
)
def test_cli_init_force_rejects_different_config_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_name: str,
    source_text: str,
    expected_guidance: str,
) -> None:
    """Refuse to shadow the user's authoritative legacy YAML or TOML source.

    Args:
        tmp_path: Project containing the alternate config source.
        monkeypatch: Fixture that makes the project the CLI working directory.
        source_name: Discovered legacy YAML or pyproject filename.
        source_text: Original source bytes that must remain unchanged.
        expected_guidance: YAML migration or TOML hand-edit term shown to the user.
    """
    monkeypatch.chdir(tmp_path)
    source = tmp_path / source_name
    source.write_text(source_text)

    result = CliRunner().invoke(main, ["init", "--force"])

    assert result.exit_code != 0
    assert expected_guidance in result.output
    assert source.read_text() == source_text
    assert not (tmp_path / ".gruff-py.yaml").exists()


def test_cli_init_force_leaves_unknown_target_bytes_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leave schema-incompatible target bytes untouched after CLI failure.

    Args:
        tmp_path: Project containing unknown target configuration.
        monkeypatch: Fixture that makes the project the CLI working directory.
    """
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".gruff-py.yaml"
    original = "schemaVersion: gruff-py.config.v0.1\nunknownSurface: keep-me\n"
    target.write_text(original)

    result = CliRunner().invoke(main, ["init", "--force"])

    assert result.exit_code != 0
    assert "left unchanged" in result.output
    assert target.read_text() == original


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="chmod 0 read-denial only enforced on POSIX as a non-root user.",
)
def test_cli_init_force_rejects_unreadable_pyproject_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create no YAML when the user's discovered TOML cannot be read.

    Args:
        tmp_path: Project containing an unreadable pyproject source.
        monkeypatch: Fixture that makes the project the CLI working directory.
    """
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "pyproject.toml"
    source.write_text('[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n')
    source.chmod(0)
    try:
        result = CliRunner().invoke(main, ["init", "--force"])
    finally:
        source.chmod(stat.S_IRUSR | stat.S_IWUSR)

    assert result.exit_code != 0
    assert "pyproject.toml" in result.output
    assert not (tmp_path / ".gruff-py.yaml").exists()


def _seed_sample_project(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def f():\n    pass\n")


def _generate_default_baseline(tmp_path: Path) -> dict[str, Any]:
    _seed_sample_project(tmp_path)
    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "src",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--generate-baseline",
        ],
    )
    assert result.exit_code == 0, result.output
    return cast("dict[str, Any]", json.loads(result.output))


def test_cli_analyse_generate_baseline_writes_default_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    generated_payload = _generate_default_baseline(tmp_path)
    baseline_payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert baseline_payload["schemaVersion"] == "gruff-py.baseline.v1"
    assert len(baseline_payload["findings"]) == len(generated_payload["findings"])
    assert generated_payload["baseline"] == {
        "applied": False,
        "entries": len(generated_payload["findings"]),
        "path": "gruff-baseline.json",
        "generated": True,
        "suppressedFindings": 0,
        "staleEvaluation": "generated",
        "staleEntries": 0,
        "source": "default",
        "stale": [],
    }


def test_cli_analyse_auto_applies_default_baseline_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    generated_payload = _generate_default_baseline(tmp_path)

    applied = CliRunner().invoke(
        main,
        ["analyse", "src", "--format", "json", "--fail-on", "warning", "--no-config"],
    )
    applied_payload = json.loads(applied.output)

    assert applied.exit_code == 0, applied.output
    assert applied_payload["findings"] == []
    assert applied_payload["baseline"]["source"] == "default"
    assert applied_payload["baseline"]["generated"] is False
    assert applied_payload["baseline"]["suppressedFindings"] == len(generated_payload["findings"])


def test_cli_analyse_baseline_option_conflicts_are_diagnostics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("x = 1\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "src",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--baseline-path",
            "gruff-baseline.json",
            "--generate-baseline",
        ],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["type"] == "baseline-error"
    assert "mutually exclusive" in payload["diagnostics"][0]["message"]


def test_cli_summary_aborts_cleanly_when_config_missing_schema_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / "pyproject.toml").write_text('[tool.gruff-py]\nminimumPythonVersion = "3.11"\n')

    result = CliRunner().invoke(main, ["summary", "src"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "missing required 'schemaVersion'" in result.stderr
    assert "gruff-py migrate-config" in result.stderr
    assert "init --force" not in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_aborts_cleanly_when_config_schema_version_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.99\n")

    result = CliRunner().invoke(main, ["analyse", "src"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "schemaVersion 'gruff-py.config.v0.99'" in result.stderr
    assert "gruff-py migrate-config" in result.stderr
    assert "init --force" not in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_json_emits_structured_config_error_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`analyse --format json` against a bad config returns a parseable
    payload with a config-error diagnostic + exit 2, not stderr prose.

    Regression for the JSON-automation case codex flagged in PR #3.

    Args:
        tmp_path: pytest-supplied per-test temp directory.
        monkeypatch: pytest fixture used to chdir into the temp project.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("paths:\n  ignore: []\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["schemaVersion"] == "gruff.analysis.v3"
    assert payload["findings"] == []
    assert len(payload["diagnostics"]) == 1
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["type"] == "config-error"
    assert "missing required 'schemaVersion'" in diagnostic["message"]
    assert "Traceback" not in result.stderr


def test_cli_summary_default_group_by_keeps_top_rules_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    assert "Top rules:" in result.output
    assert "Grouped by rule" not in result.output


def test_cli_summary_group_by_rule_text_replaces_top_rules_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Two rule violations: long function name (naming) and missing docstring (docs).
    (src / "bad.py").write_text("def x_a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v_w_x_y_z_aa_bb_cc():\n    return 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "--group-by", "rule", "src"])

    assert result.exit_code in (0, 1), result.output
    assert "Top rules:" not in result.output
    assert "Grouped by rule (showing" in result.output


def test_cli_summary_group_by_rule_json_keeps_canonical_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.py").write_text("x = 1\n")  # triggers docs.missing-module-docstring

    result = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "--group-by", "rule", "src"],
    )

    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.output)
    assert payload["schemaVersion"] == "gruff.summary.v3"
    assert "groupedRules" not in payload
    assert "topRules" not in payload


def test_cli_summary_group_by_rule_does_not_change_json_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Three module files, each triggers docs.missing-module-docstring + naming
    # depending on contents. Use bare files to drive multiple distinct rules.
    (src / "a.py").write_text("x = 1\n")
    (src / "b.py").write_text("y = 2\n")
    (src / "c.py").write_text("z = 3\n")

    grouped = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "--group-by", "rule", "src"],
    )
    plain = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "src"],
    )

    assert grouped.exit_code == plain.exit_code, grouped.output
    assert json.loads(grouped.output) == json.loads(plain.output)


def test_cli_analyse_text_emits_volume_hint_when_findings_reach_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")  # one module-docstring violation
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" in result.output
    assert "summary --group-by=rule" in result.output


def test_cli_analyse_text_suppresses_volume_hint_when_below_threshold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1000\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_text_suppresses_volume_hint_when_threshold_is_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 0\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_json_does_not_emit_volume_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output
    json.loads(result.output)  # parses cleanly


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
    assert payload["schemaVersion"] == "gruff.analysis.v3"
    assert payload["run"]["format"] == "json"


def test_cli_summary_json_is_exact_analysis_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON summary changes the schema id and removes only ``findings``.

    Args:
        tmp_path: Working directory for the invocation.
        monkeypatch: Fixture used to chdir into ``tmp_path``.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    summary_result = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "src"],
    )
    analysis_result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--no-baseline",
            "src",
        ],
    )

    assert summary_result.exit_code == 0, summary_result.output
    assert analysis_result.exit_code == 0, analysis_result.output
    summary_payload = json.loads(summary_result.output)
    expected = json.loads(analysis_result.output)
    expected["schemaVersion"] = "gruff.summary.v3"
    del expected["findings"]
    assert summary_payload == expected
    assert "Next steps" not in summary_result.output


def test_cli_summary_text_includes_path_and_elapsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Text summary renders Path/Elapsed/Baseline lines and fixed-width pillar columns.

    Args:
        tmp_path: Working directory for the invocation.
        monkeypatch: Fixture used to chdir into ``tmp_path``.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    assert "Path: src" in result.output
    assert "Elapsed:" in result.output
    assert "Baseline:" in result.output
    assert "gruff-py analyse src --generate-baseline" in result.output
    assert "\nPillars\n" in result.output
    pillar_lines = [line for line in result.output.splitlines() if line.startswith("  ") and "findings=" in line and "advisory=" in line]
    assert pillar_lines, "expected at least one canonical pillar row"
    for line in pillar_lines:
        assert line.index("findings=") == 27, line
        assert line.index("advisory=") == 42, line
        assert line.index("warning=") == 57, line
        assert line.index("error=") == 71, line


def test_cli_summary_text_hints_when_paths_were_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    cache = tmp_path / ".pytest_cache"
    cache.mkdir()
    (cache / "ignored.py").write_text("x = 2\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "."])

    assert result.exit_code == 0, result.output
    assert "1 ignored" in result.output
    assert "--include-ignored" in result.output
    assert "configured paths.ignore still applies" in result.output


@pytest.mark.parametrize("command", ("report", "summary"))
def test_report_and_summary_publish_bounded_deep_scan_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "large.py").write_text("value = 1\nvalue = 2\n")

    result = CliRunner().invoke(
        main,
        [
            command,
            "--format",
            "json",
            "--no-config",
            "--deep-scan-budget",
            "1:10000",
            "large.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["type"] == "bounded-deep-scan"
    assert payload["diagnostics"][0]["invalidatesRun"] is False


def test_cli_metric_calibration_json_is_developer_dump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def sample(value):\n    if value > 0 and value < 10:\n        return value + 1\n    return value - 1\n")

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
        "halsteadVolume",
        "maintainabilityIndex",
    }
    assert payload["top"]["cyclomatic"][0]["symbol"] == "sample"


def test_cli_quiet_suppresses_success_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_cli_analyse_emits_schema_version_and_tool_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["schemaVersion"] == "gruff.analysis.v3"
    assert payload["tool"]["name"] == "gruff-py"


def test_cli_analyse_summary_counts_at_least_two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["summary"]["discoveredFiles"] >= 2
    assert payload["summary"]["parsedFiles"] >= 2


def test_cli_analyse_emits_file_length_finding_with_full_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_cli_analyse_sarif_format_is_parseable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert run["properties"]["gruffSchemaVersion"] == "gruff.analysis.v3"


def test_cli_analyse_sarif_fixture_every_result_has_fingerprint_and_matching_rule_index() -> None:
    run = _sarif_fixture_payload()["runs"][0]
    driver_rules = run["tool"]["driver"]["rules"]
    missing_fp = [r for r in run["results"] if not r["partialFingerprints"]["gruffFingerprint"]]
    mismatched_rule_index = [r for r in run["results"] if driver_rules[r["ruleIndex"]]["id"] != r["ruleId"]]
    assert missing_fp == [], f"results missing gruffFingerprint: {missing_fp}"
    assert mismatched_rule_index == [], f"ruleIndex/ruleId mismatches: {mismatched_rule_index}"


def test_cli_analyse_sarif_fixture_artifact_uris_are_normalised() -> None:
    run = _sarif_fixture_payload()["runs"][0]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]]
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


def test_analyse_full_project_unused_private_function_keeps_registered_load_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omit deletion advice when another scanned module registers the function.

    Args:
        tmp_path: Temporary full project containing producer and consumer modules.
        monkeypatch: Fixture that makes the project the CLI working directory.

    Returns:
        None; CLI assertions prove the registered function stays out of the report.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "README.md").write_text("# Registry fixture\n")
    package = tmp_path / "src" / "mail"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('"""Mail package for registry coverage."""\n')
    (package / "formatters.py").write_text(
        '"""Format failed-email batches for the delivery UI."""\n\n'
        "def _format_failed_emails():\n"
        "    return []\n\n"
        "def _unused_control():\n"
        "    return None\n"
    )
    (package / "registry.py").write_text(
        '"""Register formatters selected by the delivery UI."""\n\n'
        "from mail.formatters import _format_failed_emails\n\n"
        "FAILED_EMAIL_FORMATTERS = {'default': _format_failed_emails}\n"
    )

    analysis_command = [
        "analyse",
        "--format",
        "json",
        "--fail-on",
        "none",
        "--no-config",
        "--no-baseline",
        "--include-rule",
        "dead-code.unused-private-function",
        ".",
    ]
    result = CliRunner().invoke(main, analysis_command)
    repeated_result = CliRunner().invoke(main, analysis_command)

    assert result.exit_code == 0, result.output
    assert repeated_result.exit_code == 0, repeated_result.output
    assert repeated_result.output == result.output
    findings = json.loads(result.output)["findings"]
    assert [finding["symbol"] for finding in findings] == ["_unused_control"]
    assert findings[0]["metadata"]["externalReferenceCoverage"] == "complete"


def test_analyse_partial_unused_private_function_suppresses_module_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep class-local advice but omit module deletion advice on a narrow scan.

    Args:
        tmp_path: Temporary project containing module and class-private helpers.
        monkeypatch: Fixture that makes the project the CLI working directory.

    Returns:
        None; CLI assertions prove narrow-scan suppression and caveat rendering.
    """
    monkeypatch.chdir(tmp_path)
    source_root = tmp_path / "src"
    source_root.mkdir()
    target = source_root / "service.py"
    target.write_text(
        '"""Serve user requests through local helper functions."""\n\n'
        "def _module_helper():\n"
        "    return 1\n\n"
        "class Service:\n"
        "    def _method_helper(self):\n"
        "        return 2\n\n"
        "    def run(self):\n"
        "        return 3\n"
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
            "--no-baseline",
            "--include-rule",
            "dead-code.unused-private-function",
            "src/service.py",
        ],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 0, result.output
    assert [finding["symbol"] for finding in payload["findings"]] == ["Service._method_helper"]
    assert payload["run"]["extensions"]["py"]["run"]["partialContextCaveat"] == (
        "partial project scan: project-wide rules may need full-project context"
    )


def test_analyse_text_partial_project_rule_caveat_for_narrow_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""Module fixture for partial-context report caveat coverage."""\n')

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "text", "--fail-on", "none", "--no-config", "--no-baseline", "src"],
    )

    assert result.exit_code == 0, result.output
    assert "Scan context\n  Caveat: partial project scan: project-wide rules may need full-project context" in result.output
    assert "  Scoring mode: full-project" in result.output
    assert "  Scope: full-project" not in result.output


def test_analyse_json_partial_project_rule_caveat_is_additive_for_narrow_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""Module fixture for partial-context report caveat coverage."""\n')

    narrow = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--no-baseline",
            "src/ok.py",
        ],
    )
    full = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline", "."],
    )

    assert narrow.exit_code == 0, narrow.output
    assert full.exit_code == 0, full.output
    narrow_payload = json.loads(narrow.output)
    full_payload = json.loads(full.output)
    assert narrow_payload["run"]["extensions"]["py"]["run"]["partialContextCaveat"] == (
        "partial project scan: project-wide rules may need full-project context"
    )
    assert "extensions" not in full_payload["run"]


def test_analyse_json_project_root_path_spellings_emit_no_partial_caveat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""Module fixture for partial-context report caveat coverage."""\n')

    for full_project_path in ("./", str(tmp_path)):
        result = CliRunner().invoke(
            main,
            [
                "analyse",
                "--format",
                "json",
                "--fail-on",
                "none",
                "--no-config",
                "--no-baseline",
                full_project_path,
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert "extensions" not in payload["run"], full_project_path


def test_analyse_diff_scoped_scan_emits_partial_context_caveat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text('"""Module fixture for diff-scope caveat coverage."""\n')
    (src / "b.py").write_text('"""Module fixture for diff-scope caveat coverage."""\n\nVALUE = 1\n')
    patch = "--- a/src/b.py\n+++ b/src/b.py\n@@ -3 +3,2 @@\n VALUE = 1\n+# touched\n"

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--no-baseline",
            "--diff",
            "-",
        ],
        input=patch,
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["extensions"]["py"]["run"]["partialContextCaveat"] == (
        "partial project scan: project-wide rules may need full-project context"
    )
    assert payload["diff"]["enabled"] is True


def test_analyse_parse_error_exits_2_even_with_fail_on_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove fatal parse diagnostics bypass the findings-only severity gate.

    Args:
        tmp_path: Project root containing a tokenizer-invalid Python file.
        monkeypatch: Fixture that makes the temporary project the CLI working directory.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "broken.py").write_text("def f():\n    pass\n  bad = 1\n# z = frob()\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline", "src"],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["parseErrors"] >= 1


def test_cli_parse_error_keeps_redacted_source_text_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Show the parse diagnostic and a safe raw-source finding for a broken file.

    Args:
        tmp_path: Temporary project root containing the broken Python file.
        monkeypatch: Fixture that makes the temporary project the CLI working directory.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    aws_key = "AKIA" + "1234567890ABCDEF"
    (src / "broken.py").write_text(f"AWS_KEY = {aws_key!r}\neval('payload')\ndef broken(:\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "text",
            "--fail-on",
            "none",
            "--no-config",
            "--no-baseline",
            "src",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "[PARSE-ERROR]" in result.output
    assert "sensitive-data.aws-access-key" in result.output
    assert "security.dangerous-function-call" not in result.output
    assert aws_key not in result.output


def test_cli_bounded_deep_scan_retains_text_rules_and_nonfatal_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    aws_key = "AKIA" + "1234567890ABCDEF"
    lines = [f"AWS_KEY = {aws_key!r}", "result = eval('payload')"]
    lines.extend(f"value_{index} = {index}" for index in range(1_000))
    (src / "large.py").write_text("\n".join(lines) + "\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
            "--no-baseline",
            "--deep-scan-budget",
            "1:1000000",
            "src/large.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["discoveredFiles"] == 1
    assert payload["summary"]["parsedFiles"] == 1
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["type"] == "bounded-deep-scan"
    assert diagnostic["invalidatesRun"] is False
    assert "maxLines=1; maxBytes=1000000; override=cli" in diagnostic["message"]
    rule_ids = {finding["ruleId"] for finding in payload["findings"]}
    assert "sensitive-data.aws-access-key" in rule_ids
    assert "size.file-length" in rule_ids
    assert "security.dangerous-function-call" not in rule_ids
    assert aws_key not in result.output


@pytest.mark.parametrize("override", ("100:100000", "off"))
def test_cli_deep_scan_budget_overrides_config_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("result = eval('payload')\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\ndeepScanBudget:\n  enabled: true\n  maxLines: 1\n  maxBytes: 1\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-baseline",
            "--deep-scan-budget",
            override,
            "sample.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert not any(item["type"] == "bounded-deep-scan" for item in payload["diagnostics"])
    assert "security.dangerous-function-call" in {finding["ruleId"] for finding in payload["findings"]}


def test_cli_rejects_partial_deep_scan_budget_override_as_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("value = 1\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--no-config",
            "--deep-scan-budget",
            "100",
            "sample.py",
        ],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["type"] == "config-error"
    assert "LINES:BYTES, or off" in payload["diagnostics"][0]["message"]


def test_cli_analyse_docs_messages_describe_intent_not_absence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "foo.py").write_text("def public_thing():\n    return 1\n")
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "text", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
    assert "needs a brief intent description" in result.output
    assert "has no docstring" not in result.output


def test_cli_analyse_html_format_renders_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_analyse_display_filter_discloses_hidden_text_and_keeps_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""This module provides descriptive fixture coverage for filter disclosure tests."""\n')

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "text",
            "--fail-on",
            "advisory",
            "--no-config",
            "--no-baseline",
            "--exclude-rule",
            "docs.missing-readme",
            "src",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "Findings: 0 shown (1 hidden by display filters; score and exit code reflect all findings)" in result.output
    assert "Exit code: 1" in result.output


def test_analyse_json_display_filter_keeps_full_run_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""This module provides descriptive fixture coverage for filter disclosure tests."""\n')

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "advisory",
            "--no-config",
            "--no-baseline",
            "--exclude-rule",
            "docs.missing-readme",
            "src",
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert "hiddenByDisplayFilter" not in payload
    assert payload["findings"] == []
    assert payload["summary"]["findings"]["total"] == 1
    assert payload["summary"]["exitCode"] == 1
    assert payload["displayFilter"]["hiddenFindings"] == 1
    assert sum(pillar["findings"] for pillar in payload["score"]["pillars"]) == 1


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


def test_cli_rejects_configured_secret_preview_before_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    aws_key = "AKIA" + "1234567890ABCDEF"
    configured_preview = "AKIA...CDEF (redacted, 20 chars)"
    stripe_key = "sk_live_" + "abcdefghijklmno" + "pqrstuvwxyz123456"
    (src / "secrets.py").write_text(f"AWS_KEY = '{aws_key}'\nSTRIPE = '{stripe_key}'\n")
    (tmp_path / ".gruff-py.yaml").write_text(f"schemaVersion: gruff-py.config.v0.1\nallowlists:\n  secretPreviews:\n    - '{configured_preview}'\n")

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "error", "src"],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []
    assert payload["diagnostics"] == [
        {
            "type": "config-error",
            "message": (
                'Config key "allowlists.secretPreviews" only accepts an empty list; '
                "remove all configured entries because secret previews no longer suppress findings."
            ),
            "invalidatesRun": True,
        }
    ]
    assert aws_key not in result.output
    assert configured_preview not in result.output


def test_cli_fail_on_error_exits_1_when_errors_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_cli_fail_on_none_exits_0_even_with_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_cli_minimum_severity_config_applies_when_no_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # warning-only file: 500 lines triggers the file-length WARNING threshold but no
    # error-tier findings.
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  analyse: error\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    # Config gates at error; warning findings present but no error findings; exit 0.
    assert result.exit_code == 0, result.output


def test_cli_fail_on_flag_wins_over_minimum_severity_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  analyse: error\n")

    # Config says "error", but --fail-on warning explicitly overrides; warning
    # findings now trigger exit 1.
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "warning", "src"],
    )

    assert result.exit_code == 1, result.output


def test_cli_minimum_severity_analyse_binary_default_is_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # File with no docstring — emits a docs.missing-module-docstring advisory.
    (src / "foo.py").write_text("def public_thing():\n    return 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--no-config", "src"])

    # Advisory finding present + binary default is advisory → exit 1.
    assert result.exit_code == 1, result.output


_LEGACY_THRESHOLD_YAML = "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.cognitive:\n    thresholds:\n      warning: 15\n      error: 30\n"

_UNKNOWN_OPTION_YAML = (
    "schemaVersion: gruff-py.config.v0.1\nrules:\n  docs.dataclass-attributes:\n    options:\n      min_fields: 6\n      allowBullet: false\n"
)


def _write_clean_legacy_project(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# demo\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""Demo module holding the greeting constant for smoke tests."""\n\nGREETING = "hello"\n')
    (tmp_path / ".gruff-py.yaml").write_text(_LEGACY_THRESHOLD_YAML)


def _write_clean_unknown_option_project(project_root: Path) -> None:
    """Create a finding-free project whose config contains one option typo.

    Args:
        project_root: Empty project that receives source, README, and config files.
    """
    (project_root / "README.md").write_text("# demo\n")
    source_root = project_root / "src"
    source_root.mkdir()
    (source_root / "ok.py").write_text('"""Demo module holding the greeting constant for smoke tests."""\n\nGREETING = "hello"\n')
    (project_root / ".gruff-py.yaml").write_text(_UNKNOWN_OPTION_YAML)


def test_cli_analyse_warns_on_legacy_rule_keys_and_proceeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "src"])

    assert result.exit_code == 0, result.output
    assert "Config warnings" in result.stdout
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in result.stderr
    assert "Accepted keys" in result.stderr
    assert "gruff-py migrate-config" in result.stderr


def test_cli_analyse_warns_on_unknown_option_and_proceeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tell users the exact ignored option while a normal scan continues.

    Args:
        tmp_path: Finding-free project containing a valid option and one typo.
        monkeypatch: Fixture that makes the configured project the working directory.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_unknown_option_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "src"])

    assert result.exit_code == 0, result.output
    assert "Config warnings" in result.stdout
    assert 'Unknown option "rules.docs.dataclass-attributes.options.allowBullet".' in result.stderr
    assert "Option ignored; registered defaults and valid sibling options still apply." in result.stderr
    assert "options.allow_bullets" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_json_carries_additive_config_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    warnings = payload["run"]["extensions"]["py"]["run"]["configWarnings"]
    assert len(warnings) == 2
    assert all("thresholds" in warning for warning in warnings)
    # Warnings are not diagnostics: the exit code stays finding-driven.
    assert payload["diagnostics"] == []


def test_cli_analyse_strict_config_fails_on_legacy_rule_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--strict-config", "src"])

    assert result.exit_code == 1
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_strict_config_json_reports_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--strict-config", "--format", "json", "src"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["diagnostics"][0]["type"] == "config-error"


def test_cli_migrate_config_dry_run_prints_diff_without_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)
    config_file = tmp_path / ".gruff-py.yaml"
    original = config_file.read_text()

    dry = CliRunner().invoke(main, ["migrate-config", "--dry-run"])

    assert dry.exit_code == 0, dry.output
    assert "threshold=30, severity=error" in dry.stdout
    assert config_file.read_text() == original


def test_cli_migrate_config_rewrites_legacy_tiers_to_rubric(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    apply_result = CliRunner().invoke(main, ["migrate-config"])

    assert apply_result.exit_code == 0, apply_result.output
    assert "Wrote" in apply_result.stdout
    migrated = yaml.safe_load((tmp_path / ".gruff-py.yaml").read_text())
    assert migrated["rules"]["complexity.cognitive"]["threshold"] == 30
    assert migrated["rules"]["complexity.cognitive"]["severity"] == "error"


def test_cli_analyse_strict_config_passes_after_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)
    migrate = CliRunner().invoke(main, ["migrate-config"])
    assert migrate.exit_code == 0, migrate.output

    rerun = CliRunner().invoke(main, ["analyse", "--strict-config", "src"])

    assert rerun.exit_code == 0, rerun.output
    assert "Warning:" not in rerun.stderr
