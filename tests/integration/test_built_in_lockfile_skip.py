"""The family's built-in lockfile skip, as a gruff-py user meets it.

A package-manager lockfile carries thousands of published integrity digests, so the entropy rule's
findings there are dropped by file name. ``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive
exclusions``) lets no surface filter in silence, so every drop is counted and published as a
built-in audit row, and every other sensitive-data rule still reads the lockfile.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

_ENTROPY_RULE = "sensitive-data.high-entropy-string"
_AWS_RULE = "sensitive-data.aws-access-key"

# Split literals so the fixtures never read as a credential to another scanner.
_SYNTHETIC_DIGEST = "q7ZxM2kPv9LtB4nR" + "w8HsD3jFy6GcT5mV" + "a1UeN0bK"
_SYNTHETIC_AWS_KEY = "AKIA" + "2222333344445555"
_LOCKFILE_NAME = "package-" + "lock.json"
_TWIN_NAME = "other.json"


@pytest.fixture
def lockfile_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write one lockfile and its byte-identical twin, so a path-based mechanism is visible.

    Args:
        tmp_path: Empty directory used as the project root for one test.
        monkeypatch: Fixture used to make that directory the process working directory.

    Returns:
        The project root the files were written into.
    """
    web = tmp_path / "web"
    web.mkdir()
    body = json.dumps({"resolvedDigest": _SYNTHETIC_DIGEST, "accessKeyId": _SYNTHETIC_AWS_KEY}, indent=2)
    (web / _LOCKFILE_NAME).write_text(body + "\n")
    (web / _TWIN_NAME).write_text(body + "\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _analyse(project_root: Path) -> dict[str, Any]:
    """Run ``analyse --format json`` over *project_root* and return the parsed report."""
    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--fail-on", "none", "--no-config", str(project_root)])
    assert result.exit_code == 0, result.output
    payload: dict[str, Any] = json.loads(result.stdout)
    return payload


def _write_project(project_root: Path, contents_by_path: dict[str, str]) -> None:
    """Write each file under *project_root*, creating its directories.

    Args:
        project_root: Empty directory used as the project root.
        contents_by_path: File contents keyed by project-relative path.
    """
    for relative_path, contents in contents_by_path.items():
        (project_root / relative_path).parent.mkdir(parents=True, exist_ok=True)
        (project_root / relative_path).write_text(contents)


def _rules_for(payload: dict[str, Any], file_path: str) -> list[str]:
    """Return the rule ids reported for one file path."""
    return [finding["ruleId"] for finding in payload["findings"] if finding["file"] == file_path]


def test_lockfile_loses_only_its_entropy_findings(lockfile_project: Path) -> None:
    """The twin keeps every rule, the lockfile loses only the entropy rule, and a credential still reports.

    Args:
        lockfile_project: Lockfile and twin, already the working directory.
    """
    payload = _analyse(lockfile_project)

    twin_rules = _rules_for(payload, f"web/{_TWIN_NAME}")
    assert _ENTROPY_RULE in twin_rules, f"the twin must still report the entropy rule: {twin_rules}"
    lockfile_rules = _rules_for(payload, f"web/{_LOCKFILE_NAME}")
    assert _ENTROPY_RULE not in lockfile_rules, f"the lockfile still reports the entropy rule: {lockfile_rules}"
    assert _AWS_RULE in lockfile_rules, f"a credential in a lockfile must still report: {lockfile_rules}"


def test_the_skip_publishes_a_built_in_audit_row(lockfile_project: Path) -> None:
    """One built-in row per lockfile that had findings, naming the file and its count.

    Args:
        lockfile_project: Lockfile and twin, already the working directory.
    """
    payload = _analyse(lockfile_project)

    rows = [row for row in payload["suppressions"] if row.get("source") == "built-in"]
    assert [row["paths"] for row in rows] == [[f"web/{_LOCKFILE_NAME}"]]
    assert rows[0]["rule"] == _ENTROPY_RULE
    assert rows[0]["suppressed"] >= 1
    # No audit row may carry matched value material (FAMILY-CONTRACT.md section 5).
    assert _SYNTHETIC_DIGEST not in json.dumps(rows)


# `summary` takes no --fail-on: it reports rather than gates.
@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(["analyse", "--fail-on", "none", "--no-config"], id="analyse"),
        pytest.param(["summary", "--no-config"], id="summary"),
    ],
)
def test_the_skip_is_counted_on_text(lockfile_project: Path, arguments: list[str]) -> None:
    """A text surface that applies the skip publishes its count, in the family wording.

    Args:
        lockfile_project: Lockfile and twin, already the working directory.
        arguments: The command and flags under test, before the scan target.
    """
    expected = f"builtInLockfile[web/{_LOCKFILE_NAME}] {_ENTROPY_RULE}: "

    result = CliRunner().invoke(main, [*arguments, str(lockfile_project)])

    assert result.exit_code == 0, result.output
    assert expected in result.stdout, f"{arguments[0]} text does not count the skip:\n{result.stdout}"


def test_test_path_class_skips_sensitive_findings_and_counts_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip a key in test, fixture and example files, count it per rule and file, and keep production code reporting.

    Args:
        tmp_path: Empty directory used as the project root.
        monkeypatch: Fixture used to make that directory the process working directory.
    """
    json_key = json.dumps({"accessKeyId": _SYNTHETIC_AWS_KEY}) + "\n"
    _write_project(
        tmp_path,
        {
            _LOCKFILE_NAME: json.dumps({"resolvedDigest": _SYNTHETIC_DIGEST}) + "\n",
            "Tests/Fixtures/keys.json": json_key,
            "examples/demo.json": json_key,
            "src/test_login.py": f"ACCESS_KEY_ID = {_SYNTHETIC_AWS_KEY!r}\n",
            "src/config.json": json_key,
            "src/latest.json": json_key,
        },
    )
    monkeypatch.chdir(tmp_path)

    payload = _analyse(tmp_path)

    key_files = sorted(finding["file"] for finding in payload["findings"] if finding["ruleId"] == _AWS_RULE)
    assert key_files == ["src/config.json", "src/latest.json"]
    built_in = [(row["index"], row["paths"][0], row["rule"]) for row in payload["suppressions"] if row.get("source") == "built-in"]
    assert built_in == [
        (0, _LOCKFILE_NAME, _ENTROPY_RULE),
        (1, "Tests/Fixtures/keys.json", _AWS_RULE),
        (2, "examples/demo.json", _AWS_RULE),
        (3, "src/test_login.py", _AWS_RULE),
    ]
