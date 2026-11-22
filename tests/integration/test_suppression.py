import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

_SYNTHETIC_AWS_KEY = "AKIA" + "1234567890ABCDEF"
_BROKEN_SOURCE_WITHOUT_SUPPRESSION = f"AWS_KEY = {_SYNTHETIC_AWS_KEY!r}\ndef broken(:\n"
_BROKEN_SOURCE_SUPPRESSION_CASES = (
    (f"# gruff: disable-file=sensitive-data.aws-access-key -- test fixture\nAWS_KEY = {_SYNTHETIC_AWS_KEY!r}\ndef broken(:\n"),
    (f"AWS_KEY = {_SYNTHETIC_AWS_KEY!r}  # gruff: disable=sensitive-data.aws-access-key -- test fixture\ndef broken(:\n"),
)


def test_gruff_disable_suppresses_only_matching_rule_on_same_line(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Suppress only the rule a same-line gruff: disable comment names, so the dangerous call on that unreachable line still reports.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings and a module with an unreachable eval call.
        monkeypatch: Changes into the project so the src operand and the config path resolve.

    Returns:
        None. Checks that the dangerous-call finding is the only finding left after same-line suppression.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def f():\n    return\n    eval('payload')  # gruff: disable=waste.unreachable-code\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--config",
            ".gruff-py.yaml",
            "--include-rule",
            "waste.unreachable-code,security.dangerous-function-call",
            "src",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [finding["ruleId"] for finding in payload["findings"]] == ["security.dangerous-function-call"]


def test_gruff_disable_next_targets_next_physical_line(tmp_path: Path, monkeypatch) -> None:
    """Apply a gruff: disable-next comment to the next physical line only, so the second eval call still reports.

    Args:
        tmp_path: Project root holding a config that enables dangerous-call findings and a module with the directive above two calls.
        monkeypatch: Changes into the project so the src operand and the config path resolve.

    Returns:
        None. Checks that exactly one finding remains and that it points to the second call.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gruff-py.yaml").write_text("schemaVersion: gruff-py.config.v0.1\nrules:\n  security.dangerous-function-call:\n    enabled: true\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("# gruff: disable-next=security.dangerous-function-call\neval('first')\neval('second')\n")

    result = CliRunner().invoke(
        main,
        [
            "analyse",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--config",
            ".gruff-py.yaml",
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
    """Confine a gruff: disable-file comment to its own file, so an unmarked module with the same 1,001-line body still reports its length.

    Args:
        tmp_path: Project root whose src folder holds the marked and the unmarked long module.
        monkeypatch: Changes into the project so the src operand resolves.

    Returns:
        None. Checks that the unmarked module produces the only file-length finding.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    long_body = "\n".join(f"x{i} = {i}" for i in range(1001)) + "\n"
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
    assert [(finding["file"], finding["ruleId"]) for finding in payload["findings"]] == [("src/visible.py", "size.file-length")]


def _analyse_broken_source(tmp_path: Path, source: str) -> tuple[int, dict]:
    """Run the JSON CLI journey for one syntactically broken source fixture.

    Args:
        tmp_path: Temporary project root that receives the fixture. Make it the working directory so the CLI finds src.
        source: Broken Python source text to write and analyse.

    Returns:
        Process status and parsed JSON analysis payload.
    """
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "broken.py").write_text(source)
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
            "src",
        ],
    )
    return result.exit_code, json.loads(result.output)


@pytest.mark.parametrize(
    "source",
    (_BROKEN_SOURCE_WITHOUT_SUPPRESSION, *_BROKEN_SOURCE_SUPPRESSION_CASES),
    ids=("no-directive", "disable-file", "disable-same-line"),
)
def test_gruff_directives_cannot_hide_sensitive_findings_in_broken_source(
    tmp_path: Path,
    monkeypatch,
    source: str,
) -> None:
    """Keep recoverable sensitive findings and the fatal diagnostic in broken Python source.

    Args:
        tmp_path: Temporary project root containing the broken Python file.
        monkeypatch: Fixture that makes the temporary project the CLI working directory.
        source: Broken source with or without a Gruff suppression directive.

    Returns:
        None. Checks the parser diagnostic, exit status, and AWS finding.
    """
    monkeypatch.chdir(tmp_path)

    status, payload = _analyse_broken_source(tmp_path, source)

    assert status == 2
    assert {diagnostic["type"] for diagnostic in payload["diagnostics"]} == {"parse-error"}
    assert any(finding["ruleId"] == "sensitive-data.aws-access-key" for finding in payload["findings"])
