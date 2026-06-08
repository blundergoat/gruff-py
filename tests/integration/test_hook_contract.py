# gruff: disable-file=test-quality.eager-test -- hook tests assert many invariants per call.
# gruff: disable-file=test-quality.loop-in-test -- loops enumerate finding rows, not cases.
# gruff: disable-file=test-quality.loop-assertion-without-message -- finding ruleId names the row.
# gruff: disable-file=test-quality.conditional-logic -- threshold branch mirrors finding shape.
# gruff: disable-file=docs.complex-branch-rationale -- threshold branch mirrors finding shape.
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
_SCOPES = {"line", "symbol", "file", "project"}


def test_hook_capabilities_advertise_contract() -> None:
    result = CliRunner().invoke(main, ["hook", "--capabilities", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["contractVersion"] == "gruff.hook.v1"
    assert payload["analyzer"] == {"name": "gruff-py", "version": VERSION}
    assert payload["supports"] == {
        "changedRanges": True,
        "diff": True,
        "baseline": True,
        "scopeField": True,
        "metadata": True,
        "stableIdentity": True,
        "ignoreReport": True,
        "newOnly": True,
    }
    assert payload["flags"] == {
        "changedRanges": "--changed-ranges",
        "diff": "--diff",
        "baseline": "--baseline",
    }
    assert payload["flagOrder"] == "any"


def test_hook_changed_ranges_omit_file_scope_and_keep_line_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    _write_long_file_with_eval(sample, eval_line=500, total_lines=1010)

    scoped = _hook("--no-config", "--changed-ranges", "500-500", "src/sample.py")
    anchor = _hook("--no-config", "--changed-ranges", "1-1", "src/sample.py")
    full = _hook("--no-config", "src/sample.py")

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
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()

    line_file = src / "line.py"
    line_file.write_text('value = eval("1")\n')
    before_shift = _finding_by_rule(
        _hook("--no-config", "src/line.py"), "security.dangerous-function-call"
    )
    line_file.write_text("# inserted\n" + line_file.read_text())
    after_shift = _finding_by_rule(
        _hook("--no-config", "src/line.py"), "security.dangerous-function-call"
    )

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
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    baseline_path = tmp_path / "hook-baseline.json"

    _write_long_file(sample, total_lines=1010)
    baseline_path.write_text(json.dumps(_hook("--no-config", "src/sample.py")))
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
    baseline_path.write_text(json.dumps(_hook("--no-config", "src/sample.py")))
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
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')
    clean_baseline = tmp_path / "clean-baseline.json"
    clean_baseline.write_text(
        json.dumps(
            {
                "contractVersion": "gruff.hook.v1",
                "findings": [],
                "suppressed": {"count": 0},
                "ignored": {"paths": []},
                "config": {"schemaOk": True, "error": None},
            }
        )
    )

    result = _invoke_hook("--no-config", "--baseline", str(clean_baseline), "src/sample.py")

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    # Nothing existed in the clean base, so a newly added finding is surfaced.
    assert "security.dangerous-function-call" in _rule_ids(payload)


@pytest.mark.skipif(_GIT is None, reason="git is required for hook --diff conformance")
def test_hook_diff_new_only_uses_stable_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "sample.py"
    _git("init")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "Test User")

    _write_long_file(sample, total_lines=900)
    _git("add", ".")
    _git("commit", "-m", "base under threshold")
    _write_long_file(sample, total_lines=1010)
    newly_crossed = _hook("--no-config", "--diff", "HEAD", "src/sample.py")
    assert "size.file-length" in _rule_ids(newly_crossed)

    _git("add", ".")
    _git("commit", "-m", "base over threshold")
    _write_long_file(sample, total_lines=1020)
    grown = _hook("--no-config", "--diff", "HEAD", "src/sample.py")
    assert "size.file-length" not in _rule_ids(grown)


@pytest.mark.parametrize("bad_range", ["abc", "5-2"])
def test_hook_rejects_malformed_changed_ranges(
    bad_range: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    result = _invoke_hook("--no-config", "--changed-ranges", bad_range, "src/sample.py")

    # A malformed range is a controlled exit 2, not an uncaught traceback.
    assert result.exit_code == 2, result.output


def test_hook_flags_parse_before_and_after_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text('value = eval("1")\n')

    result = _invoke_hook("--no-config", "src/sample.py")

    payload = json.loads(result.output)
    assert result.exit_code == 0, result.output
    assert payload["findings"]


def test_hook_reports_ignored_paths_and_config_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "ignored.py").write_text('value = eval("1")\n')
    (src / "sample.py").write_text('value = eval("1")\n')
    config = tmp_path / ".gruff-py.yaml"
    config.write_text(
        "schemaVersion: gruff-py.config.v0.1\npaths:\n  ignore:\n    - src/ignored.py\n"
    )

    ignored = _hook("src/ignored.py")
    assert ignored["ignored"]["paths"] == [
        {"path": "src/ignored.py", "source": "config", "pattern": "src/ignored.py"}
    ]
    assert ignored["findings"] == []

    config.write_text("paths:\n  ignore: []\n")
    result = _invoke_hook("--format", "json", "src/sample.py")
    payload = json.loads(result.output)
    assert result.exit_code == 2, result.output
    assert payload["config"]["schemaOk"] is False
    assert "schemaVersion" in payload["config"]["error"]
    assert "gruff-py init --force" in payload["config"]["error"]


def _hook(*args: str) -> dict[str, Any]:
    result = _invoke_hook("--format", "json", *args)
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _invoke_hook(*args: str):
    return CliRunner().invoke(main, ["hook", *args])


def _finding_by_rule(payload: dict[str, Any], rule_id: str) -> dict[str, Any]:
    matches = [finding for finding in payload["findings"] if finding["ruleId"] == rule_id]
    assert len(matches) == 1
    return matches[0]


def _rule_ids(payload: dict[str, Any]) -> set[str]:
    return {finding["ruleId"] for finding in payload["findings"]}


def _write_long_file(path: Path, *, total_lines: int) -> None:
    path.write_text('"""Utilities for hook contract conformance."""\n' + "\n" * (total_lines - 2))


def _write_long_file_with_eval(path: Path, *, eval_line: int, total_lines: int) -> None:
    lines = ['"""Utilities for hook contract conformance."""\n']
    for line in range(2, total_lines + 1):
        if line == eval_line:
            lines.append('value = eval("1")\n')
        else:
            lines.append("\n")
    path.write_text("".join(lines))


def _git(*args: str) -> None:
    subprocess.run([_GIT or "git", *args], check=True, capture_output=True, text=True)
