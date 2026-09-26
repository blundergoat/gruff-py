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
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("import os; eval('payload')  # gruff: disable=waste.unused-import\n")

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
    assert [finding["ruleId"] for finding in payload["findings"]] == ["security.dangerous-function-call"]


def test_gruff_disable_next_targets_next_physical_line(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
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
        tmp_path: Temporary project root that receives the fixture.
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
    "suppressed_source",
    _BROKEN_SOURCE_SUPPRESSION_CASES,
    ids=("disable-file", "disable-same-line"),
)
def test_parse_broken_source_text_findings_obey_suppressions(
    tmp_path: Path,
    monkeypatch,
    suppressed_source: str,
) -> None:
    """Filter a raw-source finding without hiding its parser diagnostic or exit 2.

    Args:
        tmp_path: Temporary project root containing the broken Python file.
        monkeypatch: Fixture that makes the temporary project the CLI working directory.
        suppressed_source: Broken source carrying the suppression form under test.
    """
    monkeypatch.chdir(tmp_path)

    unsuppressed_status, unsuppressed_payload = _analyse_broken_source(
        tmp_path,
        _BROKEN_SOURCE_WITHOUT_SUPPRESSION,
    )
    # An unsuppressed broken file keeps both the fatal diagnostic and recoverable text evidence.
    unsuppressed_contract = {
        "status": unsuppressed_status,
        "diagnosticTypes": {diagnostic["type"] for diagnostic in unsuppressed_payload["diagnostics"]},
        "hasAwsFinding": any(finding["ruleId"] == "sensitive-data.aws-access-key" for finding in unsuppressed_payload["findings"]),
    }
    assert unsuppressed_contract == {
        "status": 2,
        "diagnosticTypes": {"parse-error"},
        "hasAwsFinding": True,
    }

    suppressed_status, suppressed_payload = _analyse_broken_source(tmp_path, suppressed_source)
    # A matching directive removes only the source finding; parser failure still owns exit 2.
    suppressed_contract = {
        "status": suppressed_status,
        "diagnosticTypes": {diagnostic["type"] for diagnostic in suppressed_payload["diagnostics"]},
        "hasAwsFinding": any(finding["ruleId"] == "sensitive-data.aws-access-key" for finding in suppressed_payload["findings"]),
    }
    assert suppressed_contract == {
        "status": 2,
        "diagnosticTypes": {"parse-error"},
        "hasAwsFinding": False,
    }
