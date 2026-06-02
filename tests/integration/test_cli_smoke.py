# gruff: disable-file=size.file-length -- end-to-end CLI smoke covers every subcommand.
# gruff: disable-file=test-quality.eager-test -- smoke tests assert many invariants per call.
# gruff: disable-file=test-quality.loop-in-test -- loops enumerate output rows, not test cases.
# gruff: disable-file=test-quality.magic-number-assertion -- column positions are the contract.
# gruff: disable-file=test-quality.conditional-logic -- branches mirror the --format axis.
# gruff: disable-file=test-quality.loop-assertion-without-message -- row ruleId self-describes.
# gruff: disable-file=docs.complex-branch-rationale -- branches mirror the --format axis.
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from click.testing import CliRunner

from gruffpy.cli import _normalise_optional_diff_args, main
from gruffpy.version import VERSION

_EXPECTED_ROOT_COMMANDS = (
    "analyse",
    "check-ignore",
    "completion",
    "dashboard",
    "help",
    "init",
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
_GIT = shutil.which("git")


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


def test_cli_menu_keeps_a_gutter_after_the_longest_command_name():
    result = CliRunner().invoke(main, ["--no-ansi"])

    assert result.exit_code == 0
    assert "check-ignoreReport" not in result.output
    assert "check-ignore  Report whether gruff would ignore" in result.output


def test_optional_diff_args_resolves_sys_argv_for_real_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Console-script / python -m calls reach CliGroup.main with args=None; Click would
    # then read sys.argv itself, skipping normalisation. The helper must resolve
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


def test_analyse_changed_ranges_returns_only_changed_method_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(
        "def old_bad():\n    eval('old')\n\n\ndef new_bad():\n    eval('new')\n"
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
            "docs.missing-function-docstring",
            "--changed-ranges",
            "6-6",
            "src/sample.py",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [finding["symbol"] for finding in payload["findings"]] == ["new_bad"]
    assert payload["suppressedCount"] >= 1


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
    assert "changed" in {finding["symbol"] for finding in full_payload["findings"]}


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
    assert payload["suppressedCount"] >= 1
    assert payload["diff"]["suppressedCount"] == payload["suppressedCount"]


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
    assert [finding["ruleId"] for finding in symbol_payload["findings"]] == [
        "security.shell-injection"
    ]
    assert hunk.exit_code == 0, hunk.output
    assert hunk_payload["findings"] == []
    assert hunk_payload["suppressedCount"] >= 1


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
    patch = (
        "diff --git a/src/new.py b/src/new.py\n"
        "--- a/src/new.py\n"
        "+++ b/src/new.py\n"
        "@@ -2,0 +2,1 @@\n"
        "+    eval('new')\n"
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
    assert payload["diff"]["source"] == "stdin"


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
    assert payload["diff"]["source"] == expected_source
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


def test_cli_list_rules_json_lists_rule_metadata():
    result = CliRunner().invoke(main, ["list-rules", "--format", "json"])
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    rule = payload["rules"][0]
    assert set(rule) >= _REQUIRED_RULE_PAYLOAD_KEYS
    assert set(rule["documentation"]) >= _REQUIRED_RULE_DOCUMENTATION_KEYS


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
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["init"])

    target = tmp_path / ".gruff-py.yaml"
    assert result.exit_code == 0, result.output
    assert target.exists()
    assert result.output.startswith(f"Wrote {target}\n")
    assert "gruff-py analyse . --generate-baseline" in result.output


def test_cli_init_default_config_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(main, ["init"])

    config_text = (tmp_path / ".gruff-py.yaml").read_text()
    assert config_text.startswith("# gruff-py configuration - .gruff-py.yaml\n")
    assert "Built-in ignores and .gitignore already apply" in config_text
    assert "- .agents/" in config_text
    assert "- tests/fixtures/**" in config_text


def test_cli_init_refuses_to_overwrite_existing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("# do not clobber\n")

    result = CliRunner().invoke(main, ["init"])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert existing.read_text() == "# do not clobber\n"


def test_cli_analyse_does_not_prompt_when_stdin_lacks_tty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_cli_dashboard_rejects_invalid_project_root_before_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_cli_init_force_regenerates_existing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text("# do not clobber\n")

    result = CliRunner().invoke(main, ["init", "--force"])

    assert result.exit_code == 0, result.output
    assert existing.read_text().startswith("# gruff-py configuration - .gruff-py.yaml\n")


def test_cli_init_force_preserves_existing_ignore_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    existing.write_text(
        "paths:\n"
        "  ignore:\n"
        "    - generated/**\n"
        "    - .codex/\n"
        "rules:\n"
        "  docs.missing-module-docstring:\n"
        "    enabled: false\n"
    )

    result = CliRunner().invoke(main, ["init", "--force"])

    document = yaml.safe_load(existing.read_text())
    assert result.exit_code == 0, result.output
    assert document["paths"]["ignore"] == [
        "generated/**",
        ".codex/",
        ".agents/",
        ".antigravitycli/",
        ".claude/",
        ".github/",
        ".goat-flow/",
        "tests/fixtures/**",
    ]


def test_cli_init_force_refuses_to_wipe_malformed_ignore_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    existing = tmp_path / ".gruff-py.yaml"
    original = "paths:\n  ignore: generated/**\n"
    existing.write_text(original)

    result = CliRunner().invoke(main, ["init", "--force"])

    assert result.exit_code != 0
    assert "paths.ignore must be a list of strings" in result.output
    assert existing.read_text() == original


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


def test_cli_analyse_generate_baseline_writes_default_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    generated_payload = _generate_default_baseline(tmp_path)
    baseline_payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert baseline_payload["schemaVersion"] == "gruff-py.baseline.v1"
    assert len(baseline_payload["findings"]) == len(generated_payload["findings"])
    assert generated_payload["baseline"] == {
        "path": "gruff-baseline.json",
        "generated": True,
        "totalEntries": len(generated_payload["findings"]),
        "suppressedFindings": 0,
        "staleEvaluation": "generated",
        "staleEntries": 0,
        "source": "default",
        "stale": [],
    }


def test_cli_analyse_auto_applies_default_baseline_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_cli_analyse_baseline_option_conflicts_are_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_cli_summary_aborts_cleanly_when_config_missing_schema_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / "pyproject.toml").write_text('[tool.gruff-py]\nminimumPythonVersion = "3.11"\n')

    result = CliRunner().invoke(main, ["summary", "src"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "missing required 'schemaVersion'" in result.stderr
    assert "gruff-py init --force" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_aborts_cleanly_when_config_schema_version_wrong(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.99\n")

    result = CliRunner().invoke(main, ["analyse", "src"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "schemaVersion 'gruff-py.config.v0.99'" in result.stderr
    assert "gruff-py init --force" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_analyse_json_emits_structured_config_error_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert payload["schemaVersion"] == "gruff-py.analysis.v1"
    assert payload["findings"] == []
    assert len(payload["diagnostics"]) == 1
    diagnostic = payload["diagnostics"][0]
    assert diagnostic["type"] == "config-error"
    assert "missing required 'schemaVersion'" in diagnostic["message"]
    assert "Traceback" not in result.stderr


def test_cli_summary_default_group_by_keeps_top_rules_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    assert "Top rules:" in result.output
    assert "Grouped by rule" not in result.output


def test_cli_summary_group_by_rule_text_replaces_top_rules_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Two rule violations: long function name (naming) and missing docstring (docs).
    (src / "bad.py").write_text(
        "def x_a_b_c_d_e_f_g_h_i_j_k_l_m_n_o_p_q_r_s_t_u_v_w_x_y_z_aa_bb_cc():\n    return 1\n"
    )

    result = CliRunner().invoke(main, ["summary", "--no-config", "--group-by", "rule", "src"])

    assert result.exit_code in (0, 1), result.output
    assert "Top rules:" not in result.output
    assert "Grouped by rule (showing" in result.output


def test_cli_summary_group_by_rule_json_adds_grouped_rules_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert "groupedRules" in payload
    assert "topRules" in payload  # back-compat: preserved
    grouped = payload["groupedRules"]
    assert set(grouped.keys()) == {"shown", "total", "rows"}
    if grouped["rows"]:
        row = grouped["rows"][0]
        assert set(row.keys()) == {"ruleId", "count", "severity", "confidence"}


def test_cli_summary_group_by_rule_json_sorts_by_count_desc_then_rule_id_asc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Three module files, each triggers docs.missing-module-docstring + naming
    # depending on contents. Use bare files to drive multiple distinct rules.
    (src / "a.py").write_text("x = 1\n")
    (src / "b.py").write_text("y = 2\n")
    (src / "c.py").write_text("z = 3\n")

    result = CliRunner().invoke(
        main,
        ["summary", "--format", "json", "--no-config", "--group-by", "rule", "src"],
    )

    payload = json.loads(result.output)
    rows = payload["groupedRules"]["rows"]
    counts = [row["count"] for row in rows]
    assert counts == sorted(counts, reverse=True)
    # Tie-break: rule_id ASC for any two adjacent equal counts
    for i in range(len(rows) - 1):
        if rows[i]["count"] == rows[i + 1]["count"]:
            assert rows[i]["ruleId"] < rows[i + 1]["ruleId"]


def test_cli_analyse_text_emits_volume_hint_when_findings_reach_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")  # one module-docstring violation
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1\n"
    )

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" in result.output
    assert "summary --group-by=rule" in result.output


def test_cli_analyse_text_suppresses_volume_hint_when_below_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1000\n"
    )

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_text_suppresses_volume_hint_when_threshold_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 0\n"
    )

    result = CliRunner().invoke(main, ["analyse", "--format", "text", "--fail-on", "none", "src"])

    assert result.exit_code == 0, result.output
    assert "Hint:" not in result.output


def test_cli_analyse_json_does_not_emit_volume_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\noutputVolumeHintThreshold: 1\n"
    )

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
    assert payload["schemaVersion"] == "gruff-py.analysis.v1"
    assert payload["run"]["format"] == "json"


def test_cli_summary_json_is_compact_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JSON summary emits the v2 schema with pillar rows carrying numeric penalties.

    Args:
        tmp_path: Working directory for the invocation.
        monkeypatch: Fixture used to chdir into ``tmp_path``.
    """
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
    assert payload["schemaVersion"] == "gruff.summary.v2"
    assert {"summary", "pillars", "topRules", "topFiles"} <= payload.keys()
    summary = payload["summary"]
    elapsed = summary["elapsedSeconds"]
    assert summary["paths"] == ["src"]
    assert isinstance(elapsed, int | float) and elapsed >= 0
    assert "Next steps" not in result.output
    assert isinstance(payload["pillars"], list)
    assert payload["pillars"], "pillars list should not be empty"
    expected_keys = {
        "pillar",
        "grade",
        "score",
        "applicable",
        "findings",
        "advisory",
        "warning",
        "error",
        "penalty",
    }
    assert all(expected_keys <= pillar.keys() for pillar in payload["pillars"])
    for pillar in payload["pillars"]:
        assert isinstance(pillar["penalty"], int | float), (
            f"penalty should be numeric, got {type(pillar['penalty']).__name__}"
        )


def test_cli_summary_text_includes_path_and_elapsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    pillar_lines = [
        line
        for line in result.output.splitlines()
        if line.startswith("  ") and "findings=" in line and "advisory=" in line
    ]
    assert pillar_lines, "expected at least one canonical pillar row"
    for line in pillar_lines:
        assert line.index("findings=") == 27, line
        assert line.index("advisory=") == 42, line
        assert line.index("warning=") == 57, line
        assert line.index("error=") == 71, line


def test_cli_summary_text_hints_when_paths_were_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n")
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "ignored.py").write_text("x = 2\n")

    result = CliRunner().invoke(main, ["summary", "--no-config", "."])

    assert result.exit_code == 0, result.output
    assert "1 ignored" in result.output
    assert "--include-ignored" in result.output
    assert "configured paths.ignore still applies" in result.output


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


def test_cli_analyse_docs_messages_describe_intent_not_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        "schemaVersion: gruff-py.config.v0.1\n"
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


def test_cli_minimum_severity_config_applies_when_no_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # warning-only file: 500 lines triggers the file-length WARNING threshold but no
    # error-tier findings.
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  analyse: error\n"
    )

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "src"])

    # Config gates at error; warning findings present but no error findings; exit 0.
    assert result.exit_code == 0, result.output


def test_cli_fail_on_flag_wins_over_minimum_severity_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    warning_lines = "\n".join(f"x{i} = {i}" for i in range(500)) + "\n"
    (src / "warn.py").write_text(warning_lines)
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  analyse: error\n"
    )

    # Config says "error", but --fail-on warning explicitly overrides; warning
    # findings now trigger exit 1.
    result = CliRunner().invoke(
        main,
        ["analyse", "--format", "json", "--fail-on", "warning", "src"],
    )

    assert result.exit_code == 1, result.output


def test_cli_minimum_severity_analyse_binary_default_is_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # File with no docstring — emits a docs.missing-module-docstring advisory.
    (src / "foo.py").write_text("def public_thing():\n    return 1\n")

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--no-config", "src"])

    # Advisory finding present + binary default is advisory → exit 1.
    assert result.exit_code == 1, result.output
