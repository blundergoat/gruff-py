# gruff: disable-file=test-quality.loop-assertion-without-message -- finding ruleId names the row.
import ast
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from gruffpy.cli import main
from gruffpy.version import VERSION

_GIT = shutil.which("git")
_SEVERITIES = {"advisory", "warning", "error"}
# The capability set gruff.hook.v2 advertises. Every flag is on because the port implements every
# optional part of the contract; a consumer reads this map before choosing which flags to pass.
_ADVERTISED_SUPPORTS = {
    "baseline": True,
    "baselineV3": True,
    "changedRanges": True,
    "confidenceGate": True,
    "deepScanBudget": True,
    "diagnostics": True,
    "diff": True,
    "ignoreReport": True,
    "metadata": True,
    "newOnly": True,
    "scopeField": True,
    "stableIdentity": True,
}
_SCOPES = {"line", "symbol", "file", "project"}
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CODEX_HOOK_TIMEOUT_SECONDS = 90
_CODEX_PATCH_TOOL_MATCHER = "^apply_patch$"


def test_codex_registers_post_edit_quality_hook() -> None:
    """Check that the single Codex patch-tool handler names the quality hook and Node launcher and has the expected timeout and status text.

    Returns:
        None. Reads the Codex registration and checks the patch matcher and its command handler.
    """
    payload = json.loads((_REPO_ROOT / ".codex/hooks.json").read_text())

    post_tool_use = payload["hooks"]["PostToolUse"]
    assert len(post_tool_use) == 1
    # goat-flow owns this registration and matches Codex's patch tool, not the
    # Edit/Write tool names Claude uses.
    assert post_tool_use[0]["matcher"] == _CODEX_PATCH_TOOL_MATCHER
    handlers = post_tool_use[0]["hooks"]
    assert len(handlers) == 1
    handler = handlers[0]
    assert handler["type"] == "command"
    assert ".goat-flow/hooks/gruff-code-quality.mjs" in handler["command"]
    # The registration resolves the project root from the session directory.
    # It starts the Node launcher in that root to run the quality hook.
    assert ".goat-flow/hooks/run-hook.mjs" in handler["command"]
    assert handler["timeout"] == _CODEX_HOOK_TIMEOUT_SECONDS
    assert handler["statusMessage"] == "gruff code quality"


def test_hook_capabilities_advertise_contract() -> None:
    """Advertise ``gruff.hook.v2``, this analyser's name and version, every supported feature, the flag names and free flag order.

    Returns:
        None. Checks the contract fields in the hook's capability response.
    """
    result = CliRunner().invoke(main, ["hook", "--capabilities", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["contractVersion"] == "gruff.hook.v2"
    assert payload["analyzer"] == {"name": "gruff-py", "version": VERSION}
    assert payload["supports"] == _ADVERTISED_SUPPORTS
    assert payload["flags"] == {
        "baseline": "--baseline",
        "changedRanges": "--changed-ranges",
        "deepScanBudget": "--deep-scan-budget",
        "diff": "--diff",
        "failOnDiagnostics": "--fail-on-diagnostics",
        "minConfidence": "--min-confidence",
    }
    assert payload["flagOrder"] == "any"


def test_hook_changed_ranges_omit_file_scope_and_keep_line_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drop the file-length finding when changed ranges are given, with a positive suppressed count, while a changed line keeps a line-scoped finding.

    Without changed ranges, the same module reports file length with file scope.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings and a 1,011-line module with an ``eval`` call on line 500.
        monkeypatch: Changes into the project so the relative module and config paths resolve.

    Returns:
        None. Compares scoped and full hook findings and checks the suppression count for both changed ranges.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    _write_long_file_with_eval(sample, eval_line=500, total_lines=1010)

    scoped = _hook("--config", ".gruff-py.yaml", "--changed-ranges", "500-500", "src/sample.py")
    anchor = _hook("--config", ".gruff-py.yaml", "--changed-ranges", "1-1", "src/sample.py")
    full = _hook("--config", ".gruff-py.yaml", "src/sample.py")

    scoped_rules = {finding["ruleId"]: finding for finding in scoped["findings"]}
    anchor_rules = {finding["ruleId"]: finding for finding in anchor["findings"]}
    full_rules = {finding["ruleId"]: finding for finding in full["findings"]}

    assert "size.file-length" not in scoped_rules
    assert "size.file-length" not in anchor_rules
    assert scoped["suppressed"]["count"] >= 1
    assert anchor["suppressed"]["count"] >= 1
    assert scoped_rules["security.dangerous-function-call"]["scope"] == "line"
    assert full_rules["size.file-length"]["scope"] == "file"
    assert "suppressed" in full


def test_hook_findings_have_contract_fields_and_threshold_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Give every hook finding a remediation, a known severity and scope, a stable identity, metadata and complete threshold fields where present.

    Args:
        tmp_path: Project root holding a 1,011-line module with an ``eval`` call on line 10.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks required hook finding fields and validates threshold metadata when present.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    _write_long_file_with_eval(src / "sample.py", eval_line=10, total_lines=1010)

    payload = _hook("--no-config", "src/sample.py")

    assert payload["findings"]
    for finding in payload["findings"]:
        assert finding["remediation"]
        assert finding["severity"] in _SEVERITIES
        assert finding["scope"] in _SCOPES
        assert finding["stableIdentity"]
        assert finding["metadata"] is not None
        metadata = finding["metadata"]
        if "threshold" in metadata:
            assert metadata["measured"] is not None
            assert metadata["threshold"] is not None
            assert metadata["unit"]
            assert metadata["direction"] in {"above", "below"}


def test_hook_stable_identity_survives_line_shift_and_measured_value_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep a finding's stable identity while its fingerprint changes, both when an inserted line moves it and when its measured length grows.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings, a one-line ``eval`` module and a long module rewritten ten lines
            longer.
        monkeypatch: Changes into the project so the relative module and config paths resolve.

    Returns:
        None. Checks identities and fingerprints before and after a line shift and a file-length increase.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()

    line_file = src / "line.py"
    line_file.write_text('value = eval("1")\n')
    before_shift = _finding_by_rule(_hook("--config", ".gruff-py.yaml", "src/line.py"), "security.dangerous-function-call")
    line_file.write_text("# inserted\n" + line_file.read_text())
    after_shift = _finding_by_rule(_hook("--config", ".gruff-py.yaml", "src/line.py"), "security.dangerous-function-call")

    assert before_shift["stableIdentity"] == after_shift["stableIdentity"]
    assert before_shift["fingerprint"] != after_shift["fingerprint"]

    metric_file = src / "metric.py"
    _write_long_file(metric_file, total_lines=1010)
    before_growth = _finding_by_rule(_hook("--no-config", "src/metric.py"), "size.file-length")
    _write_long_file(metric_file, total_lines=1020)
    after_growth = _finding_by_rule(_hook("--no-config", "src/metric.py"), "size.file-length")

    assert before_growth["stableIdentity"] == after_growth["stableIdentity"]
    assert before_growth["fingerprint"] != after_growth["fingerprint"]


def test_hook_baseline_new_only_uses_stable_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hide a baselined file-length finding after the module grows, yet report one the module newly crosses the threshold for.

    Both outcomes hold with and without a changed range, and the grown module's changed-range run reports at least one suppressed finding.

    Args:
        tmp_path: Project root holding the rewritten module and the hook baseline generated from it.
        monkeypatch: Changes into the project so baseline generation and the hook scan its ``src`` folder.

    Returns:
        None. Checks hook findings against both baselines, with and without a changed range.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    baseline_path = tmp_path / "hook-baseline.json"

    _write_long_file(sample, total_lines=1010)
    _generate_baseline(baseline_path)
    _write_long_file(sample, total_lines=1020)
    grown = _hook("--no-config", "--baseline", str(baseline_path), "src/sample.py")
    grown_with_changed_range = _hook(
        "--no-config",
        "--changed-ranges",
        "500-500",
        "--baseline",
        str(baseline_path),
        "src/sample.py",
    )
    assert "size.file-length" not in _rule_ids(grown)
    assert "size.file-length" not in _rule_ids(grown_with_changed_range)
    assert grown_with_changed_range["suppressed"]["count"] >= 1

    _write_long_file(sample, total_lines=900)
    _generate_baseline(baseline_path)
    _write_long_file(sample, total_lines=1010)
    newly_crossed = _hook("--no-config", "--baseline", str(baseline_path), "src/sample.py")
    newly_crossed_with_changed_range = _hook(
        "--no-config",
        "--changed-ranges",
        "500-500",
        "--baseline",
        str(baseline_path),
        "src/sample.py",
    )
    assert "size.file-length" in _rule_ids(newly_crossed)
    assert "size.file-length" in _rule_ids(newly_crossed_with_changed_range)


def test_hook_baseline_with_no_findings_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept a valid v3 baseline with no occurrences, exit 0 and report the module's dangerous call as new.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings, a one-line ``eval`` module and an empty v3 baseline.
        monkeypatch: Changes into the project so the relative module and config paths resolve.

    Returns:
        None. Checks the hook's exit status and findings when the baseline contains no occurrences.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')
    clean_baseline = tmp_path / "clean-baseline.json"
    clean_baseline.write_text(
        json.dumps(
            {
                "schemaVersion": "gruff.baseline.v3",
                "toolLanguage": "py",
                "generatedAt": "2026-09-06T00:00:00+00:00",
                "occurrences": [],
                "sensitive": {"counted": 0},
            }
        )
    )

    result = _invoke_hook("--config", ".gruff-py.yaml", "--baseline", str(clean_baseline), "src/sample.py")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["run"]["baseline"] == {"applied": True, "schemaVersion": "gruff.baseline.v3", "path": "clean-baseline.json"}
    # Nothing existed in the clean base, so a newly added finding is surfaced.
    assert "security.dangerous-function-call" in _rule_ids(payload)


def test_hook_baseline_refuses_a_document_that_is_not_a_v3_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject an analysis report supplied as a baseline with a fatal diagnostic that mentions --migrate-baseline.

    Args:
        tmp_path: Temporary project the scan runs in.
        monkeypatch: Fixture used to make that project the working directory.

    Returns:
        None. Checks the hook's exit code and diagnostic when given the analysis report.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    _write_long_file(sample, total_lines=1010)

    analysis = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-baseline",
            "--no-config",
            "src/sample.py",
        ],
    )
    assert analysis.exit_code == 0, analysis.output
    baseline_path = tmp_path / "analysis-baseline.json"
    baseline_path.write_text(analysis.output)

    result = _invoke_hook("--no-config", "--baseline", str(baseline_path), "src/sample.py")

    assert result.exit_code == 2, result.output
    assert "--migrate-baseline" in result.output
    assert '"severity": "fatal"' in result.output


@pytest.mark.skipif(_GIT is None, reason="git is required for hook --diff conformance")
def test_hook_diff_new_only_uses_stable_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report new file-length findings against HEAD even when the configured display floor hides them.

    Skipped when ``git`` is not on the path.

    Args:
        tmp_path: Git repository whose module is committed under, then over, the length threshold.
        monkeypatch: Changes into the repository so git and the hook run there.

    Returns:
        None. Checks the hook's diff report against HEAD before and after the length finding enters the committed base.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    _git("init")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "Test User")
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nminimumSeverity: error\n")

    _write_long_file(sample, total_lines=900)
    _git("add", ".")
    _git("commit", "-m", "base under threshold")
    _write_long_file(sample, total_lines=1010)
    newly_crossed = _hook("--diff", "HEAD", "src/sample.py")
    assert "size.file-length" in _rule_ids(newly_crossed)

    _git("add", ".")
    _git("commit", "-m", "base over threshold")
    _write_long_file(sample, total_lines=1020)
    grown = _hook("--diff", "HEAD", "src/sample.py")
    assert "size.file-length" not in _rule_ids(grown)


def test_hook_missing_source_is_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Return exit 2 and a parseable fatal diagnostic for a missing scan operand.

    Args:
        tmp_path: Working directory without the requested file.
        monkeypatch: Changes to the fixture project.
    """
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["hook", "--no-config", "missing.py"])

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["diagnostics"][0]["severity"] == "fatal"
    assert payload["findings"] == []


@pytest.mark.skipif(_GIT is None, reason="git is required for hook --diff conformance")
def test_hook_diff_new_only_keeps_each_occurrence_beyond_the_base_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report the second ``random.randint`` token while the base still holds only the first.

    Both lines carry one hook key, because ``security.insecure-random`` names no symbol and states the same message.
    One base occurrence covers the first line. With both in the base, changing the second call's argument adds no new insecure-random finding.

    Args:
        tmp_path: Repository root holding the token module.
        monkeypatch: Moves the working directory into the repository.

    Returns:
        None. Checks the reported lines for both the surplus and equal occurrence counts.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    module = src / "tokens.py"
    _git("init")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "Test User")
    module.write_text('"""Token helpers."""\n\nimport random\n\ntoken = random.randint(0, 9)\n')
    _git("add", ".")
    _git("commit", "-m", "base with one insecure token")

    module.write_text('"""Token helpers."""\n\nimport random\n\ntoken = random.randint(0, 9)\nsecret_key = random.randint(0, 9)\n')
    surplus = _hook("--no-config", "--diff", "HEAD", "src/tokens.py")
    _git("add", ".")
    _git("commit", "-m", "base with two insecure tokens")
    module.write_text('"""Token helpers."""\n\nimport random\n\ntoken = random.randint(0, 9)\nsecret_key = random.randint(0, 99)\n')
    equal = _hook("--no-config", "--diff", "HEAD", "src/tokens.py")

    assert [finding["line"] for finding in surplus["findings"] if finding["ruleId"] == "security.insecure-random"] == [6]
    assert [finding["line"] for finding in equal["findings"] if finding["ruleId"] == "security.insecure-random"] == []


@pytest.mark.parametrize("bad_range", ["abc", "5-2"])
def test_hook_rejects_malformed_changed_ranges(
    bad_range: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 2 for a changed range that is not numeric or whose end precedes its start.

    Args:
        bad_range: Malformed range; the cases cover non-numeric text and a reversed range.
        tmp_path: Project root holding a one-line module that calls ``eval``.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks the hook's exit code for each malformed range.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    result = _invoke_hook("--no-config", "--changed-ranges", bad_range, "src/sample.py")

    assert result.exit_code == 2, result.output


def test_hook_flags_parse_before_and_after_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Produce the same JSON payload, exiting 0, whether the hook's flags come before or after the path.

    Args:
        tmp_path: Project root holding a one-line module that calls ``eval``.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks both exit codes and compares the JSON responses across the two flag positions.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    before = _invoke_hook("--no-config", "--changed-ranges", "1-1", "src/sample.py")
    after = _invoke_hook("src/sample.py", "--no-config", "--changed-ranges", "1-1")

    assert before.exit_code == 0, before.output
    assert after.exit_code == 0, after.output
    assert json.loads(before.output) == json.loads(after.output)


def test_hook_exits_zero_with_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 0 from the hook while it reports findings.

    Args:
        tmp_path: Project root holding a one-line module that calls ``eval``.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks that the hook exits successfully while reporting at least one finding.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    result = _invoke_hook("--no-config", "src/sample.py")

    payload = json.loads(result.output)
    assert result.exit_code == 0, result.output
    assert payload["findings"]


def test_hook_exclude_rule_removes_finding_from_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remove an excluded rule's finding from a hook payload that reports it without the flag.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings and a one-line ``eval`` module.
        monkeypatch: Changes into the project so the relative module and config paths resolve.

    Returns:
        None. Checks whether the dangerous-call rule appears in the hook reports with and without the exclusion flag.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    full = _hook("--config", ".gruff-py.yaml", "src/sample.py")
    excluded = _hook(
        "--config",
        ".gruff-py.yaml",
        "--exclude-rule",
        "security.dangerous-function-call",
        "src/sample.py",
    )

    assert "security.dangerous-function-call" in _rule_ids(full)
    assert "security.dangerous-function-call" not in _rule_ids(excluded)


def test_hook_exclude_rule_accepts_repeated_and_csv_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report none of the three rules named through repeated and comma-separated ``--exclude-rule`` values.

    Args:
        tmp_path: Project root holding a one-line module that calls ``eval``.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks that the hook reports none of the rules named through the two exclusion flags.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    payload = _hook(
        "--no-config",
        "--exclude-rule",
        "security.dangerous-function-call,docs.missing-module-docstring",
        "--exclude-rule",
        "docs.missing-readme",
        "src/sample.py",
    )

    assert _rule_ids(payload).isdisjoint(
        {
            "security.dangerous-function-call",
            "docs.missing-module-docstring",
            "docs.missing-readme",
        }
    )


def test_hook_publishes_nonfatal_bounded_deep_scan_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check that the CLI-budget payload reports a non-fatal bounded-deep-scan diagnostic and the AWS key rule, with the synthetic key absent.

    The payload has no dangerous-call finding for the module's ``eval`` call.

    Args:
        tmp_path: Project root holding ``large.py``, which assigns a synthetic AWS key and calls ``eval``.
        monkeypatch: Changes into the project so the relative module path resolves.

    Returns:
        None. Checks the budget diagnostic, the reported rules and the absence of the synthetic key from the JSON payload.
    """
    monkeypatch.chdir(tmp_path)
    aws_key = "AKIA" + "1234567890ABCDEF"
    (tmp_path / "large.py").write_text(f"AWS_KEY = {aws_key!r}\nresult = eval('payload')\n")

    payload = _hook(
        "--no-config",
        "--deep-scan-budget",
        "1:10000",
        "large.py",
    )

    assert payload["diagnostics"][0]["type"] == "bounded-deep-scan"
    assert payload["diagnostics"][0]["invalidatesRun"] is False
    assert "override=cli" in payload["diagnostics"][0]["message"]
    assert "sensitive-data.aws-access-key" in _rule_ids(payload)
    assert "security.dangerous-function-call" not in _rule_ids(payload)
    assert aws_key not in json.dumps(payload)


def test_hook_reports_ignored_paths_and_config_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report a config-ignored path with no findings, then exit 2 with an error object when the config lacks its schema version.

    The error names ``schemaVersion`` and the ``migrate-config`` command, not ``init --force``, and carries a remediation.

    Args:
        tmp_path: Project root whose config first ignores one of two ``eval`` modules and is then rewritten without a schema version.
        monkeypatch: Changes into the project so the hook finds its config.

    Returns:
        None. Checks the ignored-path report and the error response produced after the config is rewritten.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ignored.py").write_text('value = eval("1")\n')
    (src / "sample.py").write_text('value = eval("1")\n')
    config = tmp_path / ".gruff-py.yaml"
    config.write_text("schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - src/ignored.py\n")

    ignored = _hook("src/ignored.py")
    assert ignored["ignored"]["paths"] == [{"path": "src/ignored.py", "source": "config", "pattern": "src/ignored.py"}]
    assert ignored["findings"] == []

    config.write_text("paths:\n  ignore: []\n")
    result = _invoke_hook("--format", "json", "src/sample.py")
    payload = json.loads(result.output)
    assert result.exit_code == 2, result.output
    assert payload["config"]["schemaOk"] is False
    # The error object lets hook consumers read the remediation separately from the diagnostic message.
    assert "schemaVersion" in payload["config"]["error"]["message"]
    assert "gruff-py migrate-config" in payload["config"]["error"]["message"]
    assert "init --force" not in payload["config"]["error"]["message"]
    assert payload["config"]["error"]["remediation"]


def _generate_baseline(baseline_path: Path) -> None:
    """Write the ratified baseline v3 file the hook applies, the same file a user gets from analyse.

    Args:
        baseline_path: Destination for the generated baseline.

    Returns:
        None. Writes the baseline to baseline_path and checks that the file exists.
    """
    result = CliRunner().invoke(
        main,
        ["analyse", "--no-config", "--no-baseline", "--generate-baseline-path", str(baseline_path), "src"],
    )
    assert baseline_path.exists(), result.output


def _hook(*args: str) -> dict[str, Any]:
    """Run the hook command in JSON format and parse its payload.

    Args:
        args: Hook flags and paths, in order.

    Returns:
        The parsed payload, after asserting that the command exited 0.
    """
    result = _invoke_hook("--format", "json", *args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _invoke_hook(*args: str):
    """Invoke the hook command through Click's test runner.

    Args:
        args: Hook flags and paths, in order.

    Returns:
        The runner's result, whatever the exit code.
    """
    return CliRunner().invoke(main, ["hook", *args])


def _finding_by_rule(payload: dict[str, Any], rule_id: str) -> dict[str, Any]:
    """Pick the single finding a hook payload reports for one rule.

    Args:
        payload: Parsed hook payload whose findings are searched.
        rule_id: Rule whose finding is wanted.

    Returns:
        That finding, after asserting that exactly one matches.
    """
    matches = [finding for finding in payload["findings"] if finding["ruleId"] == rule_id]
    assert len(matches) == 1
    return matches[0]


def _rule_ids(payload: dict[str, Any]) -> set[str]:
    """Collect the rule ids a hook payload reports.

    Args:
        payload: Parsed hook payload whose findings supply the rule ids.

    Returns:
        The distinct rule ids of its findings.
    """
    return {finding["ruleId"] for finding in payload["findings"]}


def test_long_file_helpers_honor_substantive_line_contract(tmp_path: Path) -> None:
    """Both hook fixtures generate exactly the requested substantive assignments.

    Args:
        tmp_path: Temporary directory receiving the two generated Python files.

    Returns:
        None. Parses both generated files and checks their assignment counts.
    """
    plain_file = tmp_path / "plain.py"
    eval_file = tmp_path / "eval.py"

    _write_long_file(plain_file, total_lines=3)
    _write_long_file_with_eval(eval_file, eval_line=3, total_lines=3)

    plain_tree = ast.parse(plain_file.read_text())
    eval_tree = ast.parse(eval_file.read_text())
    assert sum(isinstance(statement, ast.Assign) for statement in plain_tree.body) == 3
    assert sum(isinstance(statement, ast.Assign) for statement in eval_tree.body) == 3


def _write_long_file(path: Path, *, total_lines: int) -> None:
    """Write a module made of a docstring line followed by numbered assignments.

    Args:
        path: Module to create or overwrite.
        total_lines: Number of assignment lines after the docstring line.

    Returns:
        None. Writes the module to path. A nonpositive assignment count leaves only the docstring.
    """
    # Substantive assignments, not blank padding: file-length counts substantive lines only.
    lines = ['"""Utilities for hook contract conformance."""\n']
    for line in range(2, total_lines + 2):
        lines.append(f"value_{line} = {line}\n")
    path.write_text("".join(lines))


def _write_long_file_with_eval(path: Path, *, eval_line: int, total_lines: int) -> None:
    """Write a module of substantive assignments for the hook tests, with an optional eval assignment.

    Args:
        path: Module to create or overwrite.
        eval_line: Physical line for the eval call, counting the docstring as line 1. A line outside the assignments produces no eval call.
        total_lines: Number of assignment lines after the docstring line. A nonpositive count leaves only the docstring.

    Returns:
        None. Writes the generated module to path.
    """
    lines = ['"""Utilities for hook contract conformance."""\n']
    for line in range(2, total_lines + 2):
        if line == eval_line:
            lines.append('value = eval("1")\n')
        else:
            lines.append(f"value_{line} = {line}\n")
    path.write_text("".join(lines))


def _git(*args: str) -> None:
    """Run a git command in the current directory and capture its output.

    Args:
        args: Git subcommand and its arguments.

    Returns:
        None; commands may change the current repository, and captured output is discarded.

    Raises:
        subprocess.CalledProcessError: Git exits non-zero.
    """
    subprocess.run([_GIT or "git", *args], check=True, capture_output=True, text=True)
