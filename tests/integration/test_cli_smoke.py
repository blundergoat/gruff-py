# gruff: disable-file=size.file-length -- end-to-end CLI smoke covers every subcommand.
# gruff: disable-file=test-quality.loop-assertion-without-message -- row ruleId self-describes.
"""Exercise complete CLI journeys from user-entered options to visible output.

The smoke suite protects every command's parsing, diagnostics, and report shape.
Dashboard launch tests replace the blocking HTTP server while preserving the
startup messages and validation a terminal user sees.
"""

import json
import os
import re
import shlex
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
    """Guard the root help contract across visible commands and global options.

    Returns:
        None. The assertions check the root help layout, expected commands and options, and absence of hidden commands.
    """
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
    """Print the version banner, usage, options and command list, exiting 0, when no command is given.

    Returns:
        None. The assertions check the menu text and successful exit.
    """
    result = CliRunner().invoke(main, [])

    assert result.exit_code == 0
    assert result.output.startswith(f"gruff-py {VERSION}\n\nUsage:\n")
    assert "Options:" in result.output
    assert "Available commands:" in result.output


def test_cli_root_menu_uses_ansi_colours_when_forced():
    """Check that --ansi colours the root menu's Usage heading and analyse command.

    Returns:
        None. The assertions check the expected ANSI colour codes and successful exit.
    """
    result = CliRunner().invoke(main, ["--ansi"], color=True)

    assert result.exit_code == 0
    assert "\x1b[33mUsage:\x1b" in result.output
    assert "\x1b[32manalyse\x1b" in result.output


def test_cli_menu_keeps_a_gutter_after_the_longest_command_name():
    """Keep at least two spaces between the longest command name and its description in the plain root menu.

    Returns:
        None. The assertions check command spacing in the plain menu and successful exit.
    """
    result = CliRunner().invoke(main, ["--no-ansi"])

    assert result.exit_code == 0
    assert "migrate-configRewrite" not in result.output
    assert "migrate-config  Rewrite legacy config keys" in result.output
    assert "check-ignore    Report whether gruff would ignore" in result.output


def test_optional_diff_args_resolves_sys_argv_for_real_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read ``sys.argv`` when no arguments are passed, turning a bare ``--diff`` into ``--diff=working-tree`` but keeping a named ref.

    Args:
        monkeypatch: Replaces ``sys.argv`` with a bare ``--diff`` command line, then with one that names a ref.

    Returns:
        None. The assertions check the normalised arguments for a bare flag and a named ref.
    """
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
    """Check analyse help for expected global and command options, a SARIF mention, and absence of the Args and Raises labels.

    Returns:
        None. The assertion checks the help text and successful exit.
    """
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
    """Keep the analyse help clear that parse errors bypass the findings-only severity gate.

    Returns:
        None. The assertions check the help sentence about parse errors and the help command's exit.
    """
    result = CliRunner().invoke(main, ["analyse", "--help"])
    searchable_help = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert "Gates findings only; parse errors exit 2 even with --fail-on none." in searchable_help


def test_cli_dashboard_help_labels_accepted_compatibility_options_honestly() -> None:
    """Tell dashboard users that accepted family flags have no Python behavior.

    Returns:
        None. The assertions check both compatibility labels and successful help exit.
    """
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
    """Report only the finding for new_bad in the requested range and count at least one suppressed finding.

    Args:
        tmp_path: Project root for two undocumented functions. The requested range touches new_bad and leaves old_bad out of scope.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None; the module is written into tmp_path and the assertions check retained and suppressed findings.
    """
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


@pytest.mark.parametrize(
    "ranges",
    ["=abc", ""],
    ids=["unreadable", "empty"],
)
def test_analyse_refuses_a_changed_ranges_value_it_cannot_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ranges: str,
) -> None:
    """A range the run cannot scope to ends the run, rather than widening it to the whole tree.

    Args:
        tmp_path: Project root where the test writes the module offered to the scan.
        monkeypatch: pytest fixture used to chdir into the temp directory.
        ranges: The unusable ``--changed-ranges`` value under test.

    Returns:
        None. Checks that malformed and empty ranges produce a changed-region error and an empty findings list.
    """
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
            "none",
            "--no-config",
            "--no-baseline",
            "--changed-ranges",
            ranges,
            "src/sample.py",
        ],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 2, result.output
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["changed-region"]
    assert payload["findings"] == []


@pytest.mark.parametrize(
    "ranges",
    ["=abc", ""],
    ids=["unreadable", "empty"],
)
def test_hook_refuses_a_changed_ranges_value_it_cannot_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ranges: str,
) -> None:
    """The hook holds the same contract analyse does: an unusable scope ends the run.

    Rejecting the range keeps findings from outside the requested edit out of the hook report.

    Args:
        tmp_path: Project root where the test writes the target module and invokes the hook.
        monkeypatch: pytest fixture used to chdir into the temp directory.
        ranges: The unusable ``--changed-ranges`` value under test.

    Returns:
        None. The assertions check exit 2, a fatal changed-region diagnostic and an empty findings list.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('"""Module."""\n\n\ndef changed():\n    return 1\n')

    result = CliRunner().invoke(
        main,
        [
            "hook",
            "--format",
            "json",
            "--no-config",
            "--changed-ranges",
            ranges,
            "src/sample.py",
        ],
    )

    # The hook writes its reason to stderr and the v2 payload to stdout, so the two are read apart.
    payload = json.loads(result.stdout)
    assert result.exit_code == 2, result.output
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["changed-region"]
    assert [diagnostic["severity"] for diagnostic in payload["diagnostics"]] == ["fatal"]
    assert payload["findings"] == []


def test_analyse_changed_region_fail_on_warning_gates_retained_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 1 under ``--fail-on warning`` when a changed range keeps a finding, which a full scan reports without a diff block.

    Args:
        tmp_path: Project root holding a module whose one function lacks a docstring.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None; the module is written into tmp_path and the assertions check both scan reports and exits.
    """
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
    """Suppress findings outside the changed range before the gate, so ``--fail-on warning`` exits 0 and the diff block counts them.

    Args:
        tmp_path: Project root holding a module with a documented changed function and an undocumented one outside the range.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None; the module is written into tmp_path and the assertions check the gate and suppression accounting.
    """
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
    """Anchor file length to line 1 under symbol scope: a range there keeps the finding and its metadata, while a far range suppresses it.

    A full scan also reports one file-length finding and omits the suppression count and diff block.

    Args:
        tmp_path: Project root holding a README and a module of 1,010 substantive lines built from one long list.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks that the anchor range retains the file-length finding, the far range suppresses it, and the full scan omits diff accounting.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "README.md").write_text("# Test project\n")
    src = tmp_path / "src"
    src.mkdir()
    # The list delimiters count and the module docstring is excluded, so 1008 entries produce the 1010 lines expected in finding metadata.
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
    """Gate a finding elsewhere in the changed function under symbol scope, but suppress it under hunk scope, which covers only the changed line.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings and a function that calls ``eval`` above the changed line.
        monkeypatch: Changes into the project so the relative module and config paths resolve.

    Returns:
        None. Checks that symbol scope fails the gate on the dangerous call and hunk scope suppresses the finding.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    # The changed range covers the return statement, so hunk scope excludes the finding on the eval call.
    (src / "sample.py").write_text(
        '"""Module."""\n'
        'PREFIX = "diag"\n\n\n'
        "def changed():\n"
        '    """Evaluate the legacy diagnostics expression for compatibility."""\n'
        '    command = "ls"\n'
        "    eval(command)\n"
        "    return 1\n"
    )

    common_args = [
        "analyse",
        "--format",
        "json",
        "--fail-on",
        "warning",
        "--config",
        ".gruff-py.yaml",
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
    assert [finding["ruleId"] for finding in symbol_payload["findings"]] == ["security.dangerous-function-call"]
    assert hunk.exit_code == 0, hunk.output
    assert hunk_payload["findings"] == []
    assert hunk_payload["summary"]["suppressedFindings"] >= 1


_CHANGED_SCOPE_BASE = ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline"]
_BETA_DEFINITION_LINE = 5


def _three_symbol_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a module whose alpha, beta, and gamma functions each carry documentation debt.

    The scoped tests use range 6-6 to touch beta's body while leaving its definition and both siblings outside that range.

    Args:
        tmp_path: Directory used as the project root.
        monkeypatch: Fixture used to make that directory the working directory.

    Returns:
        None; the fixture module is written and the working directory is changed for the caller.
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

    Returns:
        None. Checks full-scan findings for all three fixture symbols and the absence of changed-region accounting.
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
    """Check that symbol scope for a body edit reports beta, excludes alpha and gamma, and includes a finding on beta's definition line.

    Args:
        tmp_path: Project root for this run.
        monkeypatch: Fixture used to enter that root.

    Returns:
        None. Checks which fixture symbols appear and whether any finding is on beta's definition line.
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

    Returns:
        None. Checks that the counts reconcile with the full scan and that both reports of suppression agree.
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
    """Apply the default baseline to a changed-range scan, but let ``--no-baseline`` report and gate the changed function.

    Args:
        tmp_path: Project root holding a module with one undocumented function and the default baseline generated from it.
        monkeypatch: Changes into the project so the module path and the default baseline resolve.

    Returns:
        None; the module and baseline are written into tmp_path and the assertions check both scan results.
    """
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
    """Limit findings to the file a stdin diff names, and report the diff mode as ``stdin``.

    Args:
        tmp_path: Project root whose ``src`` folder holds two files with one undocumented function each; the diff names one.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks successful analysis, findings confined to the named file, and the reported stdin diff mode.
    """
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
    """Gate the changed function's finding through each git diff source, and report that source and the changed file in the diff block.

    Skipped when ``git`` is not on the path.

    Args:
        tmp_path: Git repository whose committed module loses its function docstring in the working tree.
        monkeypatch: Changes into the repository so git and the scan run there.
        diff_args: Diff-selecting flags; the cases cover the working tree, the index and a ``--since`` ref.
        should_stage: Whether the edit is staged before the scan.
        expected_source: Diff mode the payload must report for the case.

    Returns:
        None. Checks that the retained finding fails the gate and the diff block identifies the selected source and file.
    """
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
    """Run a Git command in the given directory and capture its text output.

    Args:
        cwd: Working directory, which may be uninitialized for git init.
        args: Git subcommand and its arguments.

    Returns:
        The successful Git process result with stdout and stderr captured as text.

    Raises:
        AssertionError: Git is not on the path.
        subprocess.CalledProcessError: Git exits non-zero.
    """
    assert _GIT is not None
    return subprocess.run(
        [_GIT, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_git_history(cwd: Path, *paths: str) -> None:
    """Create a repository whose HEAD is a root commit of the staged index, with a fixed author and committer.

    The commit is written with ``commit-tree`` and set as ``HEAD`` directly, so no git user configuration is needed.

    Args:
        cwd: Directory to initialise as the repository.
        paths: Paths to stage, relative to cwd. With no paths, the commit uses the existing index contents.

    Returns:
        None; the repository's HEAD is set to the new commit.

    Raises:
        AssertionError: Git is not on the path.
        subprocess.CalledProcessError: Any git command exits non-zero.
    """
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
# The baseline container a generate run publishes; every key is present on every run, movement or not.
_GENERATED_BASELINE_KEYS = frozenset(
    {
        "applied",
        "entries",
        "path",
        "generated",
        "newFindings",
        "resolvedFindings",
        "suppressedFindings",
        "unchangedFindings",
        "staleEvaluation",
        "staleEntries",
        "source",
        "stale",
    }
)
_MOVEMENT_COUNTERS = ("newFindings", "resolvedFindings", "suppressedFindings", "unchangedFindings", "staleEntries")


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
    """Check the first JSON catalogue entry for required metadata keys and the rationale, fix guidance and confidence rationale keys.

    Returns:
        None. The assertions check key presence in the entry and its documentation.
    """
    rule = _list_rules_payload()["rules"][0]

    assert set(rule) >= _REQUIRED_RULE_PAYLOAD_KEYS
    assert set(rule["documentation"]) >= _REQUIRED_RULE_DOCUMENTATION_KEYS


def test_cli_list_rules_json_publishes_heuristic_false_positive_shapes():
    """Publish a heuristic rule's false-positive shapes at the top of its JSON entry, not inside its documentation block.

    Returns:
        None. The assertions check for a nonempty top-level field and its absence from the documentation block.
    """
    payload = _list_rules_payload()

    heuristic_rule = next(candidate for candidate in payload["rules"] if candidate["id"] == "dead-code.unused-private-attribute")
    assert heuristic_rule["falsePositiveShapes"]
    assert "falsePositiveShapes" not in heuristic_rule["documentation"]


def test_cli_list_rules_json_publishes_thresholds_as_named_knob_maps():
    """Publish named-knob threshold maps for the checked rules in the JSON catalogue, and the retired scalar ``threshold`` key for none.

    A rule with a family knob name borrows it, another uses a one-key map, and a rule with no threshold omits the key.

    Returns:
        None. Checks the expected threshold maps and the absence of a top-level scalar threshold across the catalogue.
    """
    rules = {rule["id"]: rule for rule in _list_rules_payload()["rules"]}

    # A rubric whose rule id has a gruff-go knob name borrows it.
    assert rules["complexity.cognitive"]["thresholds"] == {"maxComplexity": 30}
    assert rules["size.function-length"]["thresholds"] == {"maxLines": 100}
    # A rubric without a registered threshold name uses threshold as the map key.
    assert rules["docs.todo-density"]["thresholds"] == {"threshold": 10}
    # A named-knob rule publishes its map unchanged.
    assert rules["test-quality.excessive-mocking"]["thresholds"] == {"maxMocks": 4}
    # A rule with no threshold omits the key.
    assert "thresholds" not in rules["security.ssrf"]
    assert [rule_id for rule_id, rule in rules.items() if "threshold" in rule] == []


def test_cli_list_rules_explain_json_publishes_the_same_threshold_map():
    """Publish the maxLines threshold map, without a scalar threshold, when one rule is explained in JSON.

    Returns:
        None. The assertions check the exit, the exact threshold map and absence of the scalar key.
    """
    result = CliRunner().invoke(main, ["list-rules", "size.function-length", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["thresholds"] == {"maxLines": 100}
    assert "threshold" not in payload


def test_cli_list_rules_accepts_text_alias():
    """Accept text as a list-rules format and print the rule and pillar columns.

    Returns:
        None. The assertions check successful exit and the Rule and Pillar labels.
    """
    result = CliRunner().invoke(main, ["list-rules", "--format", "text"])

    assert result.exit_code == 0, result.output
    assert "Rule" in result.output
    assert "Pillar" in result.output


def test_cli_list_rules_default_remains_unchanged_by_explain_mode():
    """Print the plain catalogue table from list-rules without the single-rule rationale or escape-hatch headings.

    Returns:
        None. The assertions check the catalogue headings, successful exit and absence of single-rule detail headings.
    """
    result = CliRunner().invoke(main, ["list-rules"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Rule")
    assert "Pillar" in result.output
    assert "Rationale:" not in result.output
    assert "Escape hatches:" not in result.output


def test_cli_list_rules_explain_text_renders_full_detail_view():
    """Check the text explanation of naming.short-variable for its default severity, expected section headings and selected entries.

    Returns:
        None. The assertions check the command exit, advisory severity, section headings and selected entries.
    """
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
    """Check that explaining one rule with --format table starts with the text detail heading.

    Returns:
        None. Checks the exit status and the opening rule heading.
    """
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variable", "--format", "table"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Rule: naming.short-variable")


def test_cli_list_rules_explain_json_emits_structured_payload():
    """Explain one rule in JSON with its id, pillar, default severity, related rules, option descriptions and false-positive shapes.

    Returns:
        None. Checks the required fields in the JSON rule detail.
    """
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
    """Exit 1 for a misspelt rule id, printing an unknown-rule message and the closest id to stderr without a traceback.

    Returns:
        None. Checks the exit status and the unknown-rule diagnostic on stderr.
    """
    result = CliRunner().invoke(main, ["list-rules", "naming.short-variabel"])

    assert result.exit_code == 1
    assert "Unknown rule: naming.short-variabel" in result.stderr
    assert "Did you mean: naming.short-variable" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_list_rules_explain_rule_with_no_options_omits_options_section():
    """Omit the default-options section for a rule with no per-rule options, while keeping its false-positive and related-rule sections.

    Returns:
        None. Checks which sections the rule detail includes.
    """
    # naming.abbreviation reads allowlists.acceptedAbbreviations (global), no per-rule options.
    result = CliRunner().invoke(main, ["list-rules", "naming.abbreviation"])

    assert result.exit_code == 0, result.output
    assert "Default options:" not in result.output
    assert "Common false-positive shapes:" in result.output
    assert "Related rules:" in result.output


def test_cli_list_rules_explain_rule_with_no_related_rules_shows_none_marker():
    """Check for the (none) marker when explaining a rule with no related rules.

    Returns:
        None. Checks the command succeeds and the extracted detail contains the marker.
    """
    # docs.todo-density is not a key in RELATED_RULES, so its "Related rules:"
    # block should render the "(none)" marker.
    result = CliRunner().invoke(main, ["list-rules", "docs.todo-density"])

    assert result.exit_code == 0, result.output
    related_block = result.output.split("Related rules:")[-1]
    assert "(none)" in related_block


def test_cli_init_writes_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check that init creates a starter config and reports the next command to run.

    Args:
        tmp_path: Empty project that receives the generated config.
        monkeypatch: Fixture that makes the empty project the CLI working directory.

    Returns:
        None. Checks the successful exit, file creation, written path, and baseline-generation hint.
    """
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["init"])

    target = tmp_path / ".gruff-py.yaml"
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert result.output.startswith(f"Wrote {target}\n")
    assert "gruff-py analyse . --generate-baseline" in result.output


def test_cli_init_help_describes_canonical_regeneration_boundary() -> None:
    """Check that init help includes the phrases 'all supported settings' and 'comments and formatting may change'.

    Returns:
        None. Checks the help command's exit status and wording.
    """
    result = CliRunner().invoke(main, ["init", "--help"])
    user_visible_help = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert "all supported settings" in user_visible_help
    assert "comments and formatting may change" in user_visible_help


def test_cli_init_default_config_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a starter config that opens with its title comment, notes the built-in ignores and lists the agent and fixture ignore paths.

    Args:
        tmp_path: Empty project that receives the starter config.
        monkeypatch: Changes into the project so ``init`` writes there.

    Returns:
        None. Checks the starter config's heading, ignore note, and two expected ignore entries.
    """
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(main, ["init"])

    config_text = (tmp_path / ".gruff-py.yaml").read_text()
    assert config_text.startswith("# gruff-py configuration - .gruff-py.yaml\n")
    assert "Built-in ignores and .gitignore already apply" in config_text
    assert "- .agents/" in config_text
    assert "- tests/fixtures/**" in config_text


def test_cli_init_refuses_to_overwrite_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse to replace an existing config: exit non-zero, say that it already exists and leave its text unchanged.

    Args:
        tmp_path: Project root holding a one-line config that must survive.
        monkeypatch: Changes into the project so ``init`` targets that config.

    Returns:
        None. Checks the failed exit, the refusal message, and preservation of the existing config text.
    """
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("# do not clobber\n")

    result = CliRunner().invoke(main, ["init"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert existing.read_text() == "# do not clobber\n"


def test_cli_analyse_does_not_prompt_when_stdin_lacks_tty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Analyse a project without a config or a TTY, exiting 0, with no prompt to generate a config and no config written.

    Args:
        tmp_path: Project root with no config and one small module.
        monkeypatch: Changes into the project so ``analyse`` looks for its config there.

    Returns:
        None. Checks successful analysis without a config prompt or a generated config file.
    """
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
        monkeypatch: Stubs the dashboard server so the test can observe startup and finish.
        compatibility_arguments: Non-empty dashboard flag invocation under test.

    Returns:
        None. Checks that each flag invocation exits successfully and calls the server factory once.
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
        monkeypatch: Replaces the dashboard server factory so the test can detect an attempted startup.
        remote_dashboard_host: Non-loopback host the user attempted to expose.

    Returns:
        None. Checks the refusal message, the failed exit, and that the server factory was never called.
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
        monkeypatch: Stubs the dashboard server so the acknowledged launch finishes immediately.
        remote_dashboard_host: Non-loopback host accepted after acknowledgment.

    Returns:
        None. Checks that the acknowledged launch succeeds, prints the exposure warning, and calls the server factory once.
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
    """Check that loopback dashboard launches succeed without public-access acknowledgment or a non-loopback warning.

    Args:
        monkeypatch: Stubs the dashboard server so each local launch finishes immediately.
        loopback_dashboard_host: Local-only host that needs no acknowledgment.

    Returns:
        None. Checks a successful exit, one server factory call, and the absence of the non-loopback warning.
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
    """Check that dashboard reports a directory error for a missing project root.

    Args:
        tmp_path: Working directory for the invocation.
        monkeypatch: Makes the temporary project directory the working directory.

    Returns:
        None. Checks the directory error and confirms the target receives no config file or write error.
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
    """Check that an out-of-range port is rejected before the config prompt or server startup.

    Args:
        monkeypatch: Replaces the config prompt helper and dashboard server factory with mocks.

    Returns:
        None. Checks the port error and verifies that neither mock was called.
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
    """Check that init --force writes the generated header and preserves the loaded settings.

    Args:
        tmp_path: Project containing the valid target to regenerate.
        monkeypatch: Fixture that makes the target's project the working directory.

    Returns:
        None. Checks successful regeneration, the generated header, and equality of the loaded settings.
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
    """Check that init --force preserves the existing ignore list in order.

    Args:
        tmp_path: Project containing user-selected ignore patterns.
        monkeypatch: Fixture that makes the configured project the working directory.

    Returns:
        None. Checks successful regeneration and the exact contents of paths.ignore.
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

    Returns:
        None. Checks the invalid ignore-list message, the failure status and preservation of the original YAML.
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
        source_text: Config text written to the source and checked for preservation after refusal.
        expected_guidance: Substring expected in the refusal for this source, either migrate-config or TOML.

    Returns:
        None. Checks that init fails with the expected message, preserves the source text and creates no new YAML.
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
    """Preserve schema-incompatible config text after CLI failure.

    Args:
        tmp_path: Project containing unknown target configuration.
        monkeypatch: Fixture that makes the project the CLI working directory.

    Returns:
        None. Checks that init fails, reports preservation and leaves the existing config text intact.
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
        tmp_path: Project where the test makes pyproject.toml unreadable and restores owner read and write permissions afterward.
        monkeypatch: Fixture that makes the project the CLI working directory.

    Returns:
        None. Checks that init fails, names the unreadable TOML file and creates no YAML.
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
    """Write ``src/sample.py``, a module whose one function has no docstring.

    Args:
        tmp_path: Project root that receives the ``src`` folder.

    Returns:
        None; the sample module is written under tmp_path.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def f():\n    pass\n")


def _generate_default_baseline(tmp_path: Path) -> dict[str, Any]:
    """Seed the sample project and write the default baseline from a JSON ``analyse`` run.

    Args:
        tmp_path: Project root that receives the sample module; callers make it the working directory, where the baseline is written.

    Returns:
        The generating run's parsed JSON report, after asserting that it exited 0.
    """
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


def test_cli_bare_baseline_flag_preserves_the_following_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat a file after a bare baseline flag as the scan target and write only the default baseline.

    Args:
        tmp_path: Project with one Python source file.
        monkeypatch: Changes to the fixture project.
    """
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "sample.py"
    original = "value = 1\n"
    source.write_text(original)

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--fail-on", "none", "--format", "json", "--generate-baseline", source.name])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["run"]["inputs"] == [source.name]
    assert source.read_text() == original
    assert (tmp_path / "gruff-baseline.json").is_file()


@pytest.mark.parametrize(
    ("original", "scope", "diagnostic_type"),
    [
        ('{"schemaVersion":', ("sample.py",), "baseline-error"),
        ('{"schemaVersion":"gruff.baseline.v3","toolLanguage":"py","occurrences":[]}', ("missing.py",), "missing-path"),
        ('{"schemaVersion":"gruff.baseline.v3","toolLanguage":"py","occurrences":[]}', ("--changed-ranges=", "sample.py"), "changed-region"),
    ],
)
def test_cli_failed_generation_preserves_existing_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, original: str, scope: tuple[str, ...], diagnostic_type: str
) -> None:
    """Preserve baseline bytes when the scan or an existing default baseline fails validation.

    Args:
        tmp_path: Project with the previous baseline.
        monkeypatch: Changes to the fixture project.
        original: Existing baseline contents, valid or truncated.
        scope: Scan operands and optional changed-range selection.
        diagnostic_type: Diagnostic identifying the refusal.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("value = 1\n")
    baseline = tmp_path / "gruff-baseline.json"
    baseline.write_text(original)

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--format", "json", "--generate-baseline", *scope])

    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["diagnostics"][0]["type"] == diagnostic_type
    assert baseline.read_text() == original


@pytest.mark.parametrize(
    ("gate", "expected_exit"),
    [
        (("--fail-on", "advisory", "--min-confidence", "high"), 0),
        (("--fail-on", "advisory", "--min-confidence", "medium"), 1),
        (("--fail-on", "none", "--fail-on-new"), 1),
    ],
)
def test_cli_analyse_gates_keep_the_findings_in_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gate: tuple[str, ...], expected_exit: int
) -> None:
    """Gate a new medium-confidence finding while always reporting it.

    Args:
        tmp_path: Project missing a README, with an empty v3 baseline.
        monkeypatch: Changes to the fixture project.
        gate: Severity, confidence or baseline gate under test.
        expected_exit: Exit code for the gate's decision.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("value = 1\n")
    (tmp_path / "gruff-baseline.json").write_text('{"schemaVersion":"gruff.baseline.v3","toolLanguage":"py","occurrences":[]}')

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--format", "json", "--include-rule", "docs.missing-readme", *gate])

    assert result.exit_code == expected_exit, result.output
    assert [finding["ruleId"] for finding in json.loads(result.stdout)["findings"]] == ["docs.missing-readme"]


def test_cli_analyse_generate_baseline_writes_default_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a v3 baseline that counts every reported finding, and report a generated, unapplied default baseline with zero movement.

    Args:
        tmp_path: Project root that receives the sample module and the default baseline.
        monkeypatch: Changes into the project so the baseline lands at its default path.

    Returns:
        None. Checks the generated baseline file, occurrence total and the generating run's baseline metadata.
    """
    monkeypatch.chdir(tmp_path)

    generated_payload = _generate_default_baseline(tmp_path)
    baseline_payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert baseline_payload["schemaVersion"] == "gruff.baseline.v3"
    assert baseline_payload["toolLanguage"] == "py"
    # A row can account for several findings, so compare occurrence counts with the report total.
    assert sum(row["count"] for row in baseline_payload["occurrences"]) == len(generated_payload["findings"])
    baseline = generated_payload["baseline"]
    assert set(baseline) == _GENERATED_BASELINE_KEYS
    # The generated baseline takes effect on a later scan, leaving this run's findings visible.
    assert baseline["applied"] is False
    assert baseline["generated"] is True
    assert baseline["path"] == "gruff-baseline.json"
    assert baseline["source"] == "default"
    assert baseline["entries"] == len(baseline_payload["occurrences"])
    # Generation skips baseline comparison, so movement counters stay at zero and the stale list stays empty.
    assert {counter: baseline[counter] for counter in _MOVEMENT_COUNTERS} == dict.fromkeys(_MOVEMENT_COUNTERS, 0)
    assert baseline["staleEvaluation"] == "generated"
    assert baseline["stale"] == []


def test_cli_analyse_auto_applies_default_baseline_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply the default baseline automatically on the next run, suppressing every generated finding so ``--fail-on warning`` exits 0.

    Args:
        tmp_path: Project root holding the sample module and its generated default baseline.
        monkeypatch: Changes into the project so the next run finds the default baseline.

    Returns:
        None. Checks that the next scan uses the default baseline and suppresses all findings from the generating run.
    """
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


def test_cli_text_names_a_discovered_baseline_and_no_baseline_declines_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check the default baseline path and source in text and the original finding count in JSON with --no-baseline.

    Args:
        tmp_path: Project root holding the generated default baseline.
        monkeypatch: Moves the working directory into the project.

    Returns:
        None. Generates a baseline fixture and checks both analysis runs.
    """
    monkeypatch.chdir(tmp_path)
    generated_payload = _generate_default_baseline(tmp_path)

    applied = CliRunner().invoke(main, ["analyse", "src", "--fail-on", "none", "--no-config"])
    declined = CliRunner().invoke(main, ["analyse", "src", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline"])

    assert (applied.exit_code, declined.exit_code) == (0, 0), applied.output + declined.output
    assert "  Path: gruff-baseline.json" in applied.output
    assert "  Source: default" in applied.output
    declined_payload = json.loads(declined.output)
    assert len(declined_payload["findings"]) == len(generated_payload["findings"])


def test_cli_generated_baseline_applies_in_a_copied_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a generated baseline's project-level reviews when the project is checked out somewhere else.

    ``docs.missing-readme`` was stored at an absolute path, so a copy of the project reported it again.

    Args:
        tmp_path: Parent of the original project and its copy.
        monkeypatch: Moves the working directory into each checkout in turn.

    Returns:
        None. Checks that the stored paths are relative and that the copied baseline suppresses the reviewed findings.
    """
    original = tmp_path / "original"
    (original / "src").mkdir(parents=True)
    (original / "src" / "sample.py").write_text("def undocumented(value):\n    return value\n")
    monkeypatch.chdir(original)
    generated = CliRunner().invoke(main, ["analyse", ".", "--format", "json", "--fail-on", "none", "--no-config", "--generate-baseline"])
    checkout = tmp_path / "checkout"
    shutil.copytree(original, checkout)
    monkeypatch.chdir(checkout)

    applied = CliRunner().invoke(main, ["analyse", ".", "--format", "json", "--fail-on", "none", "--no-config", "--baseline", "gruff-baseline.json"])

    stored_paths = [row["path"] for row in json.loads((checkout / "gruff-baseline.json").read_text())["occurrences"]]
    applied_payload = json.loads(applied.output)
    assert (generated.exit_code, applied.exit_code) == (0, 0), generated.output + applied.output
    assert "README.md" in stored_paths
    assert all(not Path(stored).is_absolute() for stored in stored_paths)
    assert applied_payload["findings"] == []
    assert applied_payload["baseline"]["newFindings"] == 0


def test_cli_baseline_review_stays_on_its_own_same_named_function(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report a newly undocumented function instead of letting it take a same-named function's stored review.

    Generate the baseline while only the second process is undocumented so its review must survive a new finding for the first.

    Args:
        tmp_path: Project root holding the two same-named functions.
        monkeypatch: Moves the working directory into the project.

    Returns:
        None. Checks that only the first definition has a missing-function-docstring finding after the baseline is applied.
    """
    header = '"""Two same-named helpers."""\n\n\n'
    documented = (
        'def process(a):\n    """Return the value unchanged.\n\n'
        '    Args:\n        a: The value.\n\n    Returns:\n        The value.\n    """\n    return a\n\n\n'
    )
    undocumented_first = "def process(a):\n    return a\n\n\n"
    second = "def process(b):\n    return b\n"
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "pair.py"
    source.write_text(header + documented + second)
    monkeypatch.chdir(tmp_path)
    generated = CliRunner().invoke(main, ["analyse", "src", "--format", "json", "--fail-on", "none", "--no-config", "--generate-baseline"])
    source.write_text(header + undocumented_first + second)

    applied_arguments = ["analyse", "src", "--format", "json", "--fail-on", "none", "--no-config", "--baseline", "gruff-baseline.json"]
    applied = CliRunner().invoke(main, applied_arguments)

    assert (generated.exit_code, applied.exit_code) == (0, 0), generated.output + applied.output
    visible = [finding["line"] for finding in json.loads(applied.output)["findings"] if finding["ruleId"] == "docs.missing-function-docstring"]
    assert visible == [4]


def test_cli_hook_keeps_a_review_analyse_stored_on_a_same_named_function(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Suppress the reviewed docstring finding in the hook using a baseline generated by analyse.

    Only the second of the two same-named definitions lacks a docstring.

    Args:
        tmp_path: Project root holding the two same-named functions.
        monkeypatch: Moves the working directory into the project.

    Returns:
        None. Checks that baseline generation and the hook succeed and that the hook reports no missing-function-docstring findings.
    """
    documented = (
        '"""Two same-named helpers."""\n\n\n'
        'def process(a):\n    """Return the value unchanged.\n\n'
        '    Args:\n        a: The value.\n\n    Returns:\n        The value.\n    """\n    return a\n\n\n'
        "def process(b):\n    return b\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "pair.py").write_text(documented)
    monkeypatch.chdir(tmp_path)
    generated = CliRunner().invoke(main, ["analyse", "src", "--format", "json", "--fail-on", "none", "--no-config", "--generate-baseline"])

    hooked = CliRunner().invoke(main, ["hook", "--no-config", "--baseline", "gruff-baseline.json", "src/pair.py"])

    assert (generated.exit_code, hooked.exit_code) == (0, 0), generated.output + hooked.output
    docstring_findings = [finding for finding in json.loads(hooked.output)["findings"] if finding["ruleId"] == "docs.missing-function-docstring"]
    assert docstring_findings == []


def test_cli_printed_baseline_commands_use_canonical_spellings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Copy the refusal's migration command and then the migration's tip, and meet no superseded-spelling warning.

    Args:
        tmp_path: Project holding a 0.5 baseline.
        monkeypatch: Moves the working directory into the project.

    Returns:
        None. Runs the printed commands and checks their flag spellings, exit statuses and absence of superseded-spelling warnings.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("def undocumented(value):\n    return value\n")
    (tmp_path / "legacy.json").write_text(json.dumps({"schemaVersion": "gruff-py.baseline.v1", "findings": []}))
    scan_args = ["sample.py", "--no-config", "--format", "text", "--fail-on", "none"]
    refused = CliRunner().invoke(main, ["analyse", *scan_args, "--baseline", "legacy.json"])
    printed_command = re.search(r"`gruff-py (analyse [^`]+)`", refused.output)
    migration_args = shlex.split(printed_command.group(1).replace("<new path>", "migrated.json")) if printed_command else []
    migrated = CliRunner().invoke(main, [*migration_args, *scan_args])
    printed_tip = re.search(r"rerun with `([^`]+)`", migrated.output)
    tip_args = shlex.split(printed_tip.group(1)) if printed_tip else []

    applied = CliRunner().invoke(main, ["analyse", *scan_args, *tip_args])

    assert refused.exit_code == 2, refused.output
    assert migration_args[:2] == ["analyse", "--migrate-baseline"], refused.output
    assert migrated.exit_code == 0, migrated.output
    assert tip_args == ["--baseline", "migrated.json"], migrated.output
    assert applied.exit_code == 0, applied.output
    assert [result.output for result in (migrated, applied) if "superseded" in result.output] == []


def test_cli_analyse_baseline_option_conflicts_are_diagnostics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 2 with a ``baseline-error`` diagnostic when ``--baseline`` and ``--generate-baseline`` are combined.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks that the conflicting baseline options produce exit code 2 and a baseline-error diagnostic.
    """
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
            "--baseline",
            "gruff-baseline.json",
            "--generate-baseline",
        ],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["type"] == "baseline-error"
    assert "mutually exclusive" in payload["diagnostics"][0]["message"]


def test_cli_summary_aborts_cleanly_when_config_missing_schema_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 2 from ``summary`` with empty stdout and a migrate-config hint, and no traceback, when pyproject config lacks a schema version.

    Args:
        tmp_path: Project root whose ``pyproject.toml`` holds a gruff-py table without ``schemaVersion``.
        monkeypatch: Changes into the project so ``summary`` loads that config.

    Returns:
        None. Checks the failed summary's exit status, stdout and migration guidance.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / "pyproject.toml").write_text('[tool.gruff-py]\nminimumPythonVersion = "3.11"\n')

    result = CliRunner().invoke(main, ["summary", "src"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "missing required 'schemaVersion'" in result.stderr
    assert "gruff-py migrate-config" in result.stderr
    assert "init --force" not in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_aborts_cleanly_when_config_schema_version_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 2 from ``analyse`` with empty stdout and a migrate-config hint, and no traceback, for an unknown config schema version.

    Args:
        tmp_path: Project root whose ``.gruff-py.yaml`` names an unknown schema version.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks the exit status, empty stdout and migration guidance for the unknown schema version.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.99\n")

    result = CliRunner().invoke(main, ["analyse", "src"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "schemaVersion 'gruff-py.config.v0.99'" in result.stderr
    assert "gruff-py migrate-config" in result.stderr
    assert "init --force" not in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_json_emits_structured_config_error_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check that analyse --format json reports a missing config schema version in structured JSON.

    Args:
        tmp_path: Temporary project root for the source file and invalid config.
        monkeypatch: pytest fixture used to chdir into the temp project.

    Returns:
        None. Checks exit code 2, a v3 JSON report with no findings and one config-error diagnostic, and the absence of a stderr traceback.
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


@pytest.mark.parametrize(
    ("invalid_setting", "message"),
    [
        (
            "sensitiveExclusions:\n  - rule: sensitive-data.aws-access-key\n    path: ./\n    reason: sample fixture\n",
            "must name one project-relative file",
        ),
        ("deepScanBudget:\n  1: true\n  wrong: true\n", "Unknown deepScanBudget keys"),
    ],
    ids=("empty-normalized-path", "mixed-budget-keys"),
)
def test_cli_malformed_config_still_emits_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_setting: str, message: str) -> None:
    """Publish an ordinary config-error envelope for malformed YAML settings.

    Args:
        tmp_path: Project root that receives the malformed config.
        monkeypatch: Changes into the fixture project before running analyse.
        invalid_setting: Invalid YAML setting appended to a recognized schema header.
        message: Expected error text for that setting.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\n" + invalid_setting)

    result = CliRunner().invoke(main, ["analyse", "--format", "json"])

    assert result.exit_code == 2, result.output
    (diagnostic,) = json.loads(result.stdout)["diagnostics"]
    assert diagnostic["type"] == "config-error"
    assert message in diagnostic["message"]


def test_cli_analyse_json_config_error_leaves_out_a_target_named_from_a_sibling_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A config that cannot load, with `analyse ../proj` run from a sibling directory, still publishes its envelope.

    The JSON refusal leaves run.inputs empty and omits run.config.

    Args:
        tmp_path: Parent of the target project and the sibling launch directory.
        monkeypatch: pytest fixture used to chdir into the sibling directory.

    Returns:
        None. Checks exit code 2 and the config-error envelope with empty inputs and omitted config metadata.
    """
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.py").write_text("x = 1\n")
    (tmp_path / "sib").mkdir()
    monkeypatch.chdir(tmp_path / "sib")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--config", "../missing.yaml", "../proj"])

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["run"]["inputs"] == []
    assert "config" not in payload["run"]
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["config-error"]


def test_cli_analyse_refuses_several_targets_outside_the_launch_directory_with_an_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`analyse ../a ../b` from a sibling directory publishes one target-error diagnostic and no findings.

    A multi-target run requires the launch directory to contain every target. JSON reports a refusal when any target lies outside it.

    Args:
        tmp_path: Common parent of the two targets and the sibling launch directory.
        monkeypatch: pytest fixture used to chdir into the sibling directory.

    Returns:
        None. Checks exit code 2, one run-invalidating target diagnostic and an empty findings list.
    """
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.py").write_text("x = 1\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "two.py").write_text("y = 2\n")
    (tmp_path / "sib").mkdir()
    monkeypatch.chdir(tmp_path / "sib")

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--format", "json", "../a", "../b"])

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["target-error"]
    assert payload["diagnostics"][0]["invalidatesRun"] is True
    assert payload["findings"] == []


def test_cli_analyse_accepts_one_target_outside_the_launch_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept a single analysis target passed as ../a from a sibling directory.

    Args:
        tmp_path: Parent of the target and the sibling launch directory.
        monkeypatch: pytest fixture used to chdir into the sibling directory.

    Returns:
        None. Checks that the single-target invocation exits successfully.
    """
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.py").write_text("x = 1\n")
    (tmp_path / "sib").mkdir()
    monkeypatch.chdir(tmp_path / "sib")

    single = CliRunner().invoke(main, ["analyse", "--no-config", "--format", "json", "--fail-on", "none", "../a"])

    assert single.exit_code == 0, single.output


@pytest.mark.parametrize("command", ["analyse", "summary", "report"], ids=["analyse", "summary", "report"])
def test_cli_machine_json_is_the_same_from_any_launch_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    """Compare five JSON sections when scanning the same project from its root, a sibling directory and a subdirectory.

    Args:
        tmp_path: Parent directory for the project, its sibling and an out-of-project source file.
        monkeypatch: Changes the process working directory before each command invocation.
        command: CLI subcommand to invoke. The cases cover analyse, summary and report.

    Returns:
        None. Checks that every invocation succeeds and the selected sections match.
    """
    (tmp_path / "proj" / "sub").mkdir(parents=True)
    (tmp_path / "proj" / "sample.py").write_text("def sample(used, unused):\n    return used\n")
    (tmp_path / "stray.py").write_text("def stray(unused):\n    pass\n")
    (tmp_path / "sib").mkdir()

    gate = [] if command == "summary" else ["--fail-on", "none"]

    def stable(launch_directory: Path, target: str) -> str:
        """Change the process working directory, run the command, and return the sections compared across launch directories.

        Args:
            launch_directory: Directory the command is launched from.
            target: The project operand as typed from that directory.

        Returns:
            The compared sections as sorted JSON; missing sections have null values.
        """
        monkeypatch.chdir(launch_directory)
        result = CliRunner().invoke(main, [command, "--no-config", "--format", "json", *gate, target])
        assert result.exit_code == 0, f"{command} {target}: {result.output}"
        payload = json.loads(result.stdout)
        return json.dumps({key: payload.get(key) for key in ("findings", "score", "summary", "paths", "diagnostics")}, sort_keys=True)

    inside = stable(tmp_path / "proj", ".")
    assert stable(tmp_path / "sib", "../proj") == inside
    assert stable(tmp_path / "proj" / "sub", "..") == inside


@pytest.mark.parametrize("output_format", ["json", "sarif"], ids=["json", "sarif"])
def test_cli_machine_output_names_no_host_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output_format: str) -> None:
    """Check that analyse JSON and SARIF stdout omit the fixture's absolute path as a literal string.

    Require a project-level pytest finding so both formats exercise path handling when such a finding is present.

    Args:
        tmp_path: Parent of the scanned project and launch directory. Its absolute path is checked for leaks.
        monkeypatch: pytest fixture used to chdir into a sibling of the project.
        output_format: Format passed to analyse with --format, either json or sarif.

    Returns:
        None. Checks that each format includes the pytest finding and omits the fixture's absolute path.
    """
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "proj"\n\n[tool.pytest.ini_options]\naddopts = ""\n')
    (project / "test_sample.py").write_text("def test_sample():\n    assert 1 + 1 == 2\n")
    (tmp_path / "sib").mkdir()
    monkeypatch.chdir(tmp_path / "sib")

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--format", output_format, "--fail-on", "none", str(project)])

    assert result.exit_code == 0, result.output
    assert "test-quality.pytest-deprecations-not-fatal" in result.stdout
    assert str(tmp_path) not in result.stdout


def test_cli_config_error_envelope_names_no_host_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A config the run cannot load is reported in the envelope by its project-relative name, never its host path.

    Args:
        tmp_path: Parent of the project and launch directories. Its absolute path is checked for leaks in JSON.
        monkeypatch: pytest fixture used to chdir into a sibling of the project.

    Returns:
        None. Checks the config-error envelope, its relative config name and the absence of the fixture's absolute path.
    """
    project = tmp_path / "proj"
    project.mkdir()
    (project / "sample.py").write_text("x = 1\n")
    (project / ".gruff-py.yaml").write_text('schemaVersion: "gruff-py.config.v0.1"\nminimumSeverity:\n  analyse: error\n')
    (tmp_path / "sib").mkdir()
    monkeypatch.chdir(tmp_path / "sib")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", str(project)])

    assert result.exit_code == 2, result.output
    diagnostic = json.loads(result.stdout)["diagnostics"][0]
    assert diagnostic["type"] == "config-error"
    assert diagnostic["message"].startswith(".gruff-py.yaml: ")
    assert str(tmp_path) not in result.stdout


def test_cli_baseline_paths_are_read_from_the_launch_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A baseline path typed two levels inside the project names the file from there, for writing and for reading.

    Args:
        tmp_path: Parent of the nested project, also checked for a misplaced baseline file.
        monkeypatch: pytest fixture used to chdir into a nested directory of the project.

    Returns:
        None. Checks that the baseline is written in the project and can be applied from the launch directory.
    """
    project = tmp_path / "outer" / "proj"
    (project / "a" / "b").mkdir(parents=True)
    (project / "sample.py").write_text("def probe(rx):\n    return rx + rx\n")
    monkeypatch.chdir(project / "a" / "b")
    flags = ["--no-config", "--fail-on", "none"]

    generated = CliRunner().invoke(main, ["analyse", *flags, "--generate-baseline=../../base.json", "../.."])
    applied = CliRunner().invoke(main, ["analyse", *flags, "--format", "json", "--baseline", "../../base.json", "../.."])

    assert generated.exit_code == 0, generated.output
    assert (project / "base.json").is_file()
    assert not (tmp_path / "base.json").exists()
    assert applied.exit_code == 0, applied.output
    baseline = json.loads(applied.stdout)["baseline"]
    assert baseline["applied"] is True
    assert baseline["path"] == "base.json"


def test_cli_summary_default_group_by_keeps_top_rules_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Show the top-rules block, and no grouped-by-rule block, in a default text summary.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks which rule sections appear in the default text summary.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    assert "Top rules:" in result.output
    assert "Grouped by rule" not in result.output


def test_cli_summary_group_by_rule_text_replaces_top_rules_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the top-rules block with the grouped-by-rule block in a text summary under ``--group-by rule``.

    Args:
        tmp_path: Project root holding a module with one long, undocumented function name.
        monkeypatch: Changes into the project so the summary scans its ``src`` folder.

    Returns:
        None. Checks which rule sections appear with grouping enabled.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.py").write_text("def x_a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v_w_x_y_z_aa_bb_cc():\n    return 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "--group-by", "rule", "src"])

    assert result.exit_code in (0, 1), result.output
    assert "Top rules:" not in result.output
    assert "Grouped by rule (showing" in result.output


def test_cli_summary_group_by_rule_shows_mixed_severity_breakdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Render compact per-severity counts for mixed rules in ``summary --group-by rule`` while keeping single-severity rows unchanged.

    Args:
        tmp_path: Project root holding one production file and one test file with undocumented functions.
        monkeypatch: Changes into the project so the summary scans both directories together.

    Returns:
        None. Asserts mixed-severity formatting for docs.missing-function-docstring and single-severity formatting for docs.missing-module-docstring.
    """
    monkeypatch.chdir(tmp_path)
    src_dir = tmp_path / "src"
    tests_dir = tmp_path / "tests"
    src_dir.mkdir()
    tests_dir.mkdir()
    (src_dir / "mod.py").write_text("def prod_fn():\n    return 1\n")
    (tests_dir / "test_mod.py").write_text('"""Tests."""\n\ndef test_one():\n    assert True\n')

    result = CliRunner().invoke(main, ["summary", "--no-config", "--group-by", "rule", "src", "tests"])

    assert result.exit_code == 0, result.output
    assert "2  docs.missing-function-docstring  1 warning, 1 advisory  high" in result.output
    assert "1  docs.missing-module-docstring    advisory               high" in result.output


def test_cli_summary_group_by_rule_json_keeps_canonical_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report the ``gruff.summary.v3`` schema under ``--group-by rule``, with no grouped or top-rules key in the JSON.

    Args:
        tmp_path: Project root holding one module without a docstring.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the schema version and omitted presentation keys in the JSON summary.
    """
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
    """Produce identical JSON summaries and exit codes with and without ``--group-by rule``.

    Args:
        tmp_path: Project root holding three one-line modules without docstrings.
        monkeypatch: Changes into the project so both summaries scan the same source folder.

    Returns:
        None. Compares the exit statuses and decoded JSON for the two summary invocations.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Missing module docstrings supply findings under the default rules.
    # Repeated rule hits make any grouping introduced by the flag visible in the JSON comparison.
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
    """Print a hint pointing to ``summary --group-by=rule`` when the finding count reaches the configured volume threshold.

    Args:
        tmp_path: Project root whose config sets the hint threshold to 1, with one module missing its docstring.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks that the text report includes the hint and its suggested rule-grouped summary command.
    """
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
    """Print no volume hint when the finding count stays below the configured threshold.

    Args:
        tmp_path: Project root whose config sets the hint threshold to 1,000, with one module missing its docstring.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks that the small text scan succeeds and omits the volume hint.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1000\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_text_suppresses_volume_hint_when_threshold_is_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Print no volume hint when the configured threshold is 0.

    Args:
        tmp_path: Project root whose config sets the hint threshold to 0, with one module missing its docstring.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks that a zero threshold suppresses the hint in a successful text scan.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 0\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_json_does_not_emit_volume_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the volume hint out of JSON output, which stays parseable, even when the threshold is reached.

    Args:
        tmp_path: Project root whose threshold-1 config would trigger the hint in text output.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks that the CLI succeeds and emits parseable JSON without a volume hint.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output
    json.loads(result.output)  # Decoding the whole response also catches stray text outside the JSON.


def test_cli_report_writes_json_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write a ``gruff.analysis.v3`` JSON report to the ``--output`` file and print nothing.

    Args:
        tmp_path: Project root holding one small module and receiving ``report.json``.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the written report and the empty command output.
    """
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

    Returns:
        None. Asserts equality with the expected analysis projection.
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

    Returns:
        None. Checks the summary labels, baseline generation hint and pillar column positions.
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
    """Count a built-in ignored path in the text summary and point to ``--include-ignored``, noting that configured ignores still apply.

    Args:
        tmp_path: Project root holding one module in ``src`` and one inside a ``.pytest_cache`` folder.
        monkeypatch: Changes into the project so the ``.`` operand is its root.

    Returns:
        None. Checks the ignored-path count and the explanation of the flag's scope.
    """
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
    """Publish a non-fatal ``bounded-deep-scan`` diagnostic in a report command's JSON output under a CLI deep-scan budget.

    Args:
        tmp_path: Project root holding a two-line ``large.py`` that exceeds the one-line budget.
        monkeypatch: Changes into the project so the module operand resolves.
        command: Command under test; the cases vary which report command runs.

    Returns:
        None. Checks the successful exit and the non-invalidating JSON diagnostic.
    """
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
    """Dump the metric-calibration JSON schema, function count, three metric names and top function for a one-function project.

    Args:
        tmp_path: Project root holding one function with a compound condition.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the calibration schema, function count, metric names and top cyclomatic result.
    """
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
    """Print nothing under ``--quiet`` for a successful JSON analysis.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks that quiet JSON analysis succeeds with empty CLI output.
    """
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


# Past one and a half times the 1000-line limit, so file length reports at its own severity, not as a notice.
_LONG_FIXTURE_LINE_COUNT = 1600
_FINGERPRINT_HEX_LENGTH = 16


def _analyse_short_and_long_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Analyse a project holding a one-line module and a 1,600-line module, with no config.

    Args:
        tmp_path: Project root that receives the short and long modules.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        The parsed JSON report, after asserting that the command exited 0.
    """
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
    """Report the ``gruff.analysis.v3`` schema and the ``gruff-py`` tool name in JSON analysis output.

    Args:
        tmp_path: Project root that receives the short and long modules.
        monkeypatch: Lets the helper change into the project.

    Returns:
        None. Checks the analysis schema version and the tool name in the parsed JSON.
    """
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["schemaVersion"] == "gruff.analysis.v3"
    assert payload["tool"]["name"] == "gruff-py"


def test_cli_analyse_summary_counts_at_least_two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Count at least the two modules as discovered and parsed in the JSON summary.

    Args:
        tmp_path: Project root that receives the short and long modules.
        monkeypatch: Lets the helper change into the project.

    Returns:
        None. Checks that both JSON summary counts reach at least two files.
    """
    payload = _analyse_short_and_long_payload(tmp_path, monkeypatch)
    assert payload["summary"]["discoveredFiles"] >= 2
    assert payload["summary"]["parsedFiles"] >= 2


def test_cli_analyse_emits_file_length_finding_with_full_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report one file-length finding with a 16-character fingerprint, a line count at least as large as the long fixture and full classification.

    The classification is error severity in the size pillar, tier v0.1, with high confidence.

    Args:
        tmp_path: Project root that receives the short and long modules.
        monkeypatch: Lets the helper change into the project.

    Returns:
        None. Checks the sole file-length finding's fingerprint, line-count lower bound and classification.
    """
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
    """Emit SARIF 2.1.0 naming the ``gruff-py`` driver, with a gruff fingerprint on the first result.

    Args:
        tmp_path: Project root holding a 1,001-line module that yields findings.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Parses the SARIF report and checks its version, driver and first result fingerprint.
    """
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


def test_cli_reports_outside_source_links_in_json_and_sarif(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report a refused source link in both machine formats without publishing its external location.

    Args:
        tmp_path: Parent of the project and the external source file.
        monkeypatch: Launches the CLI from the project directory.

    Returns:
        None. Checks the refusal and surviving diagnostic location in both outputs.
    """
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "outside.py"
    external.write_text("value = 1\n")
    try:
        (project / "link.py").symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("creating source symlinks requires platform support")
    monkeypatch.chdir(project)
    runner = CliRunner()

    native = runner.invoke(main, ["analyse", "--no-config", "--format", "json", "."])
    sarif = runner.invoke(main, ["analyse", "--no-config", "--format", "sarif", str(project / "missing.py"), "."])

    assert (native.exit_code, sarif.exit_code) == (2, 2)
    payload = json.loads(native.stdout)
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["target-error"]
    assert payload["findings"] == []
    assert str(external) not in native.stdout + sarif.stdout
    notifications = json.loads(sarif.stdout)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    locations = [item["physicalLocation"]["artifactLocation"]["uri"] for entry in notifications for item in entry.get("locations", [])]
    assert locations == ["missing.py"]


def test_cli_reports_a_symlink_loop_as_a_fatal_json_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep JSON readable and exit 2 when an explicitly requested source link points to itself.

    Args:
        tmp_path: Project containing the circular source link.
        monkeypatch: Launches the command from the project root.

    Returns:
        None. Checks the exit, diagnostic type and missing-input count.
    """
    source = tmp_path / "loop.py"
    try:
        source.symlink_to(source.name)
    except (OSError, NotImplementedError):
        pytest.skip("creating source symlinks requires platform support")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--format", "json", source.name])

    assert result.exit_code == 2, result.exception
    payload = json.loads(result.stdout)
    assert [diagnostic["type"] for diagnostic in payload["diagnostics"]] == ["missing-path"]
    assert payload["summary"]["missingPaths"] == 1
    assert payload["findings"] == []


def _sarif_fixture_payload() -> dict:
    """Analyse the repository's complexity fixtures in SARIF format with no config.

    The fixture path is relative, so the test session must run from the repository root.

    Returns:
        The parsed SARIF payload, after asserting that the command exited 0.
    """
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
    """Advertise SARIF 2.1.0, the gruff-py driver and the gruff.analysis.v3 schema in the fixture run's SARIF output.

    Returns:
        None. Checks the SARIF version, driver name and gruff schema version.
    """
    payload = _sarif_fixture_payload()
    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "gruff-py"
    assert run["properties"]["gruffSchemaVersion"] == "gruff.analysis.v3"


def test_cli_analyse_sarif_fixture_every_result_has_fingerprint_and_matching_rule_index() -> None:
    """Give every SARIF result for the complexity fixtures a gruff fingerprint and a rule index that points at its own rule.

    Returns:
        None. Checks every fixture result for a fingerprint and a matching rule index.
    """
    run = _sarif_fixture_payload()["runs"][0]
    driver_rules = run["tool"]["driver"]["rules"]
    missing_fp = [r for r in run["results"] if not r["partialFingerprints"]["gruffFingerprint"]]
    mismatched_rule_index = [r for r in run["results"] if driver_rules[r["ruleIndex"]]["id"] != r["ruleId"]]
    assert missing_fp == [], f"results missing gruffFingerprint: {missing_fp}"
    assert mismatched_rule_index == [], f"ruleIndex/ruleId mismatches: {mismatched_rule_index}"


def test_cli_analyse_sarif_fixture_artifact_uris_are_normalised() -> None:
    """Require each complexity-fixture result's first SARIF location to omit leading ./ and Windows path separators.

    Returns:
        None. Checks URI prefixes and path separators in the first locations.
    """
    run = _sarif_fixture_payload()["runs"][0]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]]
    bad = [uri for uri in uris if uri.startswith("./") or "\\" in uri]
    assert bad == [], f"un-normalised artifact URIs: {bad}"


def test_cli_analyse_text_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check for the gruff-py banner and the Findings and Score labels in text analysis output.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the exit status and the expected text in the report.
    """
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


def test_analyse_text_partial_project_rule_caveat_for_narrow_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Show the partial-project caveat in the text scan context for a ``src`` scan, with full-project scoring and no full-project scope line.

    Args:
        tmp_path: Project root whose ``src`` folder holds one documented module.
        monkeypatch: Changes into the project so ``src`` is a narrow path inside it.

    Returns:
        None. Checks the caveat, scoring mode and omitted full-project scope line.
    """
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
    """Add the partial-context caveat as a JSON run extension for a single-file scan, and no extensions for a full-project scan.

    Args:
        tmp_path: Project root holding one documented module.
        monkeypatch: Changes into the project so ``.`` is its root and the module path is narrow.

    Returns:
        None. Checks the single-file caveat and the absence of extensions for the full-project scan.
    """
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
    """Emit no partial-context extension when the project root is given as ``./`` or as its absolute path.

    Args:
        tmp_path: Project root holding one documented module, also passed by its absolute path.
        monkeypatch: Changes into the project so ``./`` names its root.

    Returns:
        None. Checks that both root spellings succeed and omit the JSON run extensions.
    """
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
    """Add the partial-context caveat to a stdin diff-scoped scan and mark the diff block enabled.

    Args:
        tmp_path: Project root holding two documented modules; the diff touches one.
        monkeypatch: Changes into the project so the diff's paths resolve.

    Returns:
        None. Checks the partial-context caveat and enabled diff flag for the patch read from stdin.
    """
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

    Returns:
        None. Checks exit code 2 and a positive parse-error count with findings-based failure disabled.
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

    Returns:
        None. Checks the parse failure, surviving text finding and key redaction.
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
    """Keep text-based rules running under a one-line deep-scan budget, with a non-fatal diagnostic naming the CLI limits.

    The module still reports the AWS key pattern and file length, never echoes the key, and has no dangerous-call finding.

    Args:
        tmp_path: Project root holding a 1,002-line module that assigns a synthetic AWS key and calls ``eval``.
        monkeypatch: Changes into the project so the module path resolves.

    Returns:
        None. Checks the successful exit, budget diagnostic, surviving findings and key redaction.
    """
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
    """Let a larger or disabled CLI deep-scan budget override the config's one-byte budget, so the dangerous call reports with no bounded diagnostic.

    Args:
        tmp_path: Project root holding a one-line ``eval`` module and a config with a one-line, one-byte budget and dangerous calls on.
        monkeypatch: Changes into the project so the config and module resolve.
        override: CLI budget; the cases cover a larger limit pair and turning the budget off.

    Returns:
        None. Checks that each override restores the dangerous-call finding and clears the bounded-scan diagnostic.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("result = eval('payload')\n")
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\ndeepScanBudget:\n  enabled: true\n  maxLines: 1\n  maxBytes: 1\n"
        "rules:\n  security.dangerous-function-call:\n    enabled: true\n"
    )

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
    """Exit 2 with a JSON ``config-error`` diagnostic when the deep-scan budget gives lines without bytes.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the module path resolves.

    Returns:
        None. Checks the error status, diagnostic type and accepted budget syntax.
    """
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
    """Word the missing-docstring message as the intent a docstring needs, not as an absence.

    Args:
        tmp_path: Project root holding one undocumented public function.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the exit status and the missing-docstring wording.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "foo.py").write_text("def public_thing():\n    return 1\n")
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "text", "--fail-on", "none", "--no-config", "src"],
    )
    assert result.exit_code == 0, result.output
    assert "needs a docstring with a brief intent description" in result.output
    assert "has no docstring" not in result.output


def test_cli_analyse_html_format_renders_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check that --format html emits an HTML doctype and paper layout marker without the text-format label.

    Args:
        tmp_path: Project root holding one small module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks that the scan succeeds and verifies the expected markers in its HTML output.
    """
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
    """Show only error findings under ``--min-severity error``, and record the active filter in the JSON run.

    Args:
        tmp_path: Project root holding a 500-line and a 1,600-line module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the active JSON filter and verifies that the displayed findings have error severity.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    error_lines = "\n".join(f"x{i} = {i}" for i in range(1600)) + "\n"
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
    """Disclose one hidden finding, keep the canonical tally at zero and still exit 1 under ``--fail-on advisory``.

    Args:
        tmp_path: Project root without a README, holding one documented module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks the zero tally, hidden-finding disclosure and exit code in the filtered text report.
    """
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
            "--hide-rule",
            "docs.missing-readme",
            "src",
        ],
    )

    assert result.exit_code == 1, result.output
    # FAMILY-CONTRACT section 1 fixes the tally text. The disclosure explains why exit 1 can accompany a zero tally.
    assert "Findings: 0 total · 0 error · 0 warning · 0 advisory" in result.output
    assert "  Display filters hid 1 findings; score and exit code reflect all findings." in result.output
    assert "Exit code: 1" in result.output


def test_analyse_json_display_filter_keeps_full_run_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that hiding the only JSON finding preserves the full-run finding total, exit code and combined score-pillar count.

    Args:
        tmp_path: Project root without a README, holding one documented module.
        monkeypatch: Changes into the project so the scan runs from its root.

    Returns:
        None. Checks the empty display list and verifies that the hidden finding still counts in the summary and score.
    """
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
            "--hide-rule",
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


def test_configured_display_floor_reports_the_same_delta_as_the_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report equal displayFilter metadata for a configured error floor and the matching CLI flag.

    Args:
        tmp_path: Project root holding the source fixture and the config that sets the error floor.
        monkeypatch: Moves the working directory into the project.

    Returns:
        None. Compares the filtered findings and display metadata from the two runs.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text('"""This module provides descriptive fixture coverage for filter disclosure tests."""\n')
    (tmp_path / "floor.yaml").write_text('schemaVersion: "gruff-py.config.v0.1"\nminimumSeverity: error\n')
    run_args = ["analyse", "src", "--format", "json", "--fail-on", "none", "--no-baseline"]

    configured = CliRunner().invoke(main, [*run_args, "--config", "floor.yaml"])
    flagged = CliRunner().invoke(main, [*run_args, "--no-config", "--min-severity", "error"])

    configured_payload, flagged_payload = json.loads(configured.output), json.loads(flagged.output)
    assert (configured.exit_code, flagged.exit_code) == (0, 0), configured.output + flagged.output
    assert configured_payload["findings"] == flagged_payload["findings"] == []
    assert configured_payload["displayFilter"] == flagged_payload["displayFilter"]
    assert configured_payload["displayFilter"]["hiddenFindings"] == configured_payload["summary"]["findings"]["total"]


def test_cli_analyse_accepts_comma_separated_pillar_filters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept a comma-separated ``--show-pillar`` value and record both pillars, in order, in the JSON run filters.

    Args:
        tmp_path: Project root holding a 1,001-line module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Checks that the scan succeeds and preserves the requested pillar order in the JSON filters.
    """
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
            "--show-pillar",
            "size,documentation",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["filters"]["includePillars"] == ["size", "documentation"]


def test_cli_rejects_configured_secret_preview_before_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse a config that sets the removed ``allowlists.secretPreviews`` key: exit 2 with one run-invalidating config error and no findings.

    Neither the synthetic AWS key nor the configured preview text appears in the output.

    Args:
        tmp_path: Project root holding a module with two synthetic keys and a config that lists a redacted key preview.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Checks the config error, empty findings and omission of the key and preview.
    """
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
                'Config key "allowlists.secretPreviews" is removed in 0.6.0: FAMILY-CONTRACT.md section 5 '
                "makes category markers unconditional, so the key authorises nothing; delete it from the "
                "configuration."
            ),
            "invalidatesRun": True,
        }
    ]
    assert aws_key not in result.output
    assert configured_preview not in result.output


def test_cli_fail_on_error_exits_1_when_errors_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 1 under ``--fail-on error`` for a project holding a 1,600-line module.

    Args:
        tmp_path: Project root holding a 1,600-line module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Writes the long module and checks for exit code 1 under the explicit error gate.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_lines = "\n".join(f"x{i} = {i}" for i in range(1600)) + "\n"
    (src / "long.py").write_text(long_lines)

    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "error", "--no-config", "src"],
    )
    assert result.exit_code == 1


def test_cli_fail_on_none_exits_0_even_with_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 0 under ``--fail-on none`` for a project holding a 1,001-line module.

    Args:
        tmp_path: Project root holding a 1,001-line module.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Writes the long module and checks that the scan exits successfully with the gate disabled.
    """
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


def test_cli_fail_on_config_applies_when_no_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply the config's ``error`` gate when no ``--fail-on`` flag is given, so a project holding a 500-line module exits 0.

    Args:
        tmp_path: Project root holding a 500-line module and a config that gates ``analyse`` at ``error``.
        monkeypatch: Changes into the project so ``analyse`` loads that config.

    Returns:
        None. Writes the module and config and checks for exit code 0 with the configured error gate.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Keep the module at the same size as in test_cli_fail_on_flag_wins_over_fail_on_config so the gate inputs are comparable.
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nfailOn:\n  analyse: error\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    # This run leaves the gate selection to the project config.
    assert result.exit_code == 0, result.output


def test_cli_fail_on_flag_wins_over_fail_on_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Check for exit code 1 on a 500-line module with --fail-on warning and a configured error gate.

    Args:
        tmp_path: Project root holding a 500-line module and a config that gates ``analyse`` at ``error``.
        monkeypatch: Changes into the project so the flag competes with that config.

    Returns:
        None. Writes the module and config, then checks the exit status with the explicit warning gate.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nfailOn:\n  analyse: error\n")

    # The command line and project config specify different gates to exercise their precedence.
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "warning", "src"],
    )

    assert result.exit_code == 1, result.output


def test_cli_fail_on_analyse_binary_default_is_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 1 with no ``--fail-on`` flag or config for a module whose public function lacks a docstring.

    Args:
        tmp_path: Project root holding one undocumented public function.
        monkeypatch: Changes into the project so the ``src`` operand resolves.

    Returns:
        None. Writes the undocumented module and checks for exit code 1 with the built-in gate.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Leave the module undocumented to exercise the default gate on a documentation case.
    (src / "foo.py").write_text("def public_thing():\n    return 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--no-config", "src"])

    # With config disabled and no gate flag, this status exercises the built-in default.
    assert result.exit_code == 1, result.output


_LEGACY_THRESHOLD_YAML = "schemaVersion: gruff-py.config.v0.1\nrules:\n  complexity.cognitive:\n    thresholds:\n      warning: 15\n      error: 30\n"

_UNKNOWN_OPTION_YAML = (
    "schemaVersion: gruff-py.config.v0.1\nrules:\n  docs.dataclass-attributes:\n    options:\n      min_fields: 6\n      allowBullet: false\n"
)


def _write_clean_legacy_project(tmp_path: Path) -> None:
    """Write a README, one documented module and a config that still uses legacy warning and error threshold tiers.

    Args:
        tmp_path: Project root that receives the three files.

    Returns:
        None; the fixture files are written under tmp_path.
    """
    (tmp_path / "README.md").write_text("# demo\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text('"""Demo module holding the greeting constant for smoke tests."""\n\nGREETING = "hello"\n')
    (tmp_path / ".gruff-py.yaml").write_text(_LEGACY_THRESHOLD_YAML)


def _write_clean_unknown_option_project(project_root: Path) -> None:
    """Create a finding-free project whose config contains one option typo.

    Args:
        project_root: Empty project that receives source, README, and config files.

    Returns:
        None; the fixture files are written under project_root.
    """
    (project_root / "README.md").write_text("# demo\n")
    source_root = project_root / "src"
    source_root.mkdir()
    (source_root / "ok.py").write_text('"""Demo module holding the greeting constant for smoke tests."""\n\nGREETING = "hello"\n')
    (project_root / ".gruff-py.yaml").write_text(_UNKNOWN_OPTION_YAML)


def test_cli_analyse_warns_on_legacy_rule_keys_and_proceeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 0 on legacy threshold keys, with a config-warnings notice on stdout and the key, "Accepted keys" label and migrate-config hint on stderr.

    Args:
        tmp_path: Project root holding the clean legacy project.
        monkeypatch: Changes into the project so commands load its legacy config.

    Returns:
        None. Checks the successful scan and verifies that the legacy-key warning includes migration guidance.
    """
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

    Returns:
        None. Checks that analysis succeeds and tells the user which option was ignored and which spelling is accepted.
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
    """Carry two threshold config warnings as a JSON run extension, not as diagnostics, and exit 0.

    Args:
        tmp_path: Project root holding the clean legacy project.
        monkeypatch: Changes into the project so commands load its legacy config.

    Returns:
        None. Checks that both threshold warnings appear in the run extension and that analysis exits successfully.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    warnings = payload["run"]["extensions"]["py"]["run"]["configWarnings"]
    assert len(warnings) == 2
    assert all("thresholds" in warning for warning in warnings)
    # Consumers receive these config warnings through the run extension, with an empty diagnostics list for this run.
    assert payload["diagnostics"] == []


def test_cli_analyse_strict_config_fails_on_legacy_rule_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 2 under ``--strict-config`` for legacy threshold keys, naming the unknown key on stderr without a traceback.

    Args:
        tmp_path: Project root holding the clean legacy project.
        monkeypatch: Changes into the project so commands load its legacy config.

    Returns:
        None. Checks the strict scan's exit status and stderr for a clean rejection of the legacy key.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--strict-config", "src"])

    assert result.exit_code == 2
    assert 'Unknown threshold "rules.complexity.cognitive.thresholds.warning"' in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_strict_config_json_reports_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report a JSON ``config-error`` diagnostic and exit 2 when ``--strict-config`` rejects legacy threshold keys.

    Args:
        tmp_path: Project root holding the clean legacy project.
        monkeypatch: Changes into the project so commands load its legacy config.

    Returns:
        None. Checks the exit status and first JSON diagnostic from the strict scan.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    result = CliRunner().invoke(main, ["analyse", "--strict-config", "--format", "json", "src"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["diagnostics"][0]["type"] == "config-error"


def test_cli_migrate_config_dry_run_prints_diff_without_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Print the migrated threshold and severity under ``migrate-config --dry-run`` without changing the config file.

    Args:
        tmp_path: Project root holding the clean legacy project.
        monkeypatch: Changes into the project so ``migrate-config`` reads its legacy config.

    Returns:
        None. Checks the proposed threshold and severity in stdout and compares the config with its original contents.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)
    config_file = tmp_path / ".gruff-py.yaml"
    original = config_file.read_text()

    dry = CliRunner().invoke(main, ["migrate-config", "--dry-run"])

    assert dry.exit_code == 0, dry.output
    assert "threshold=30, severity=error" in dry.stdout
    assert config_file.read_text() == original


def test_cli_migrate_config_rewrites_legacy_tiers_to_rubric(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Write the migrated config to the ``--output`` file, with the error tier as threshold and severity, and leave the original unchanged.

    Args:
        tmp_path: Project root holding the clean legacy project and receiving ``migrated.yaml``.
        monkeypatch: Changes into the project so the relative output path lands there.

    Returns:
        None. Checks the migrated threshold and severity and verifies that the source config keeps its contents.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)

    original = (tmp_path / ".gruff-py.yaml").read_text()

    apply_result = CliRunner().invoke(main, ["migrate-config", "--output", "migrated.yaml"])

    assert apply_result.exit_code == 0, apply_result.output
    assert "Wrote" in apply_result.stdout
    migrated = yaml.safe_load((tmp_path / "migrated.yaml").read_text())
    assert migrated["rules"]["complexity.cognitive"]["threshold"] == 30
    assert migrated["rules"]["complexity.cognitive"]["severity"] == "error"
    # The separate output lets users review the migration while keeping the contents of the legacy config.
    assert (tmp_path / ".gruff-py.yaml").read_text() == original


def test_cli_migrate_config_rejects_a_hard_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a legacy config intact when the requested destination shares its inode.

    Args:
        tmp_path: Project with a legacy config and a hard-linked alias.
        monkeypatch: Changes to the fixture project.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)
    config = tmp_path / ".gruff-py.yaml"
    original = config.read_bytes()
    alias = tmp_path / "alias.yaml"
    alias.hardlink_to(config)

    result = CliRunner().invoke(main, ["migrate-config", "--output", alias.name])

    assert result.exit_code == 1, result.output
    assert "different file" in result.output
    assert config.read_bytes() == original


def test_cli_migrate_config_refuses_conflicting_gate_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse to choose between two different thresholds for the same command.

    Args:
        tmp_path: Project containing both gate mappings.
        monkeypatch: Changes to the fixture project.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("minimumSeverity:\n  analyse: advisory\nfailOn:\n  analyse: error\n")
    destination = tmp_path / "migrated.yaml"

    result = CliRunner().invoke(main, ["migrate-config", "--output", destination.name])

    assert result.exit_code == 1, result.output
    assert "conflicting exit gates" in result.output
    assert not destination.exists()


def test_cli_analyse_strict_config_passes_after_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pass ``--strict-config`` once the migrated config replaces the legacy one, with no ``Warning:`` text on stderr.

    Args:
        tmp_path: Project root whose legacy config is replaced by its migrated copy.
        monkeypatch: Changes into the project so migration and the strict rerun use its config file.

    Returns:
        None. Installs the migrated config and checks that the strict scan succeeds with the warning marker absent from stderr.
    """
    monkeypatch.chdir(tmp_path)
    _write_clean_legacy_project(tmp_path)
    migrate = CliRunner().invoke(main, ["migrate-config", "--output", "migrated.yaml"])
    assert migrate.exit_code == 0, migrate.output
    # The strict rerun uses the default config path, so install the migrated copy there.
    (tmp_path / ".gruff-py.yaml").write_text((tmp_path / "migrated.yaml").read_text())

    rerun = CliRunner().invoke(main, ["analyse", "--strict-config", "src"])

    assert rerun.exit_code == 0, rerun.output
    assert "Warning:" not in rerun.stderr
