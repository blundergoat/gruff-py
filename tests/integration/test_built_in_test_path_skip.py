"""The family's built-in test-path skip, as a gruff-py user meets it.

Test, fixture and example files hold sample credentials, so sensitive-data findings there are dropped by path.
``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) lets no surface filter in silence, so every drop is
counted and published as a built-in audit row, and production files keep reporting.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

_AWS_RULE = "sensitive-data.aws-access-key"

# Split so the fixtures never read as a credential to another scanner.
_SYNTHETIC_AWS_KEY = "AKIA" + "2222333344445555"


@pytest.fixture
def sample_key_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write one AWS-shaped key into three test-path files and two production files.

    Args:
        tmp_path: Empty directory used as the project root for one test.
        monkeypatch: Fixture used to make that directory the process working directory.

    Returns:
        The project root the files were written into.
    """
    json_key = json.dumps({"accessKeyId": _SYNTHETIC_AWS_KEY}) + "\n"
    contents_by_path = {
        "Tests/Fixtures/keys.json": json_key,
        "examples/demo.json": json_key,
        "src/test_login.py": f"ACCESS_KEY_ID = {_SYNTHETIC_AWS_KEY!r}\n",
        "src/config.json": json_key,
        "src/latest.json": json_key,
    }
    for relative_path, contents in contents_by_path.items():
        (tmp_path / relative_path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative_path).write_text(contents)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _analyse(project_root: Path) -> dict[str, Any]:
    """Run ``analyse --format json`` over *project_root* and return the parsed report."""
    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--fail-on", "none", "--no-config", str(project_root)])
    assert result.exit_code == 0, result.output
    payload: dict[str, Any] = json.loads(result.stdout)
    return payload


def test_test_path_class_skips_sensitive_findings_and_counts_them(sample_key_project: Path) -> None:
    """Skip a key in test, fixture and example files, count it per rule and file, and keep production code reporting.

    Args:
        sample_key_project: Key files in test and production paths, already the working directory.
    """
    payload = _analyse(sample_key_project)
    key_files = sorted(finding["file"] for finding in payload["findings"] if finding["ruleId"] == _AWS_RULE)
    built_in_rows = [row for row in payload["suppressions"] if row.get("source") == "built-in"]

    # `src/latest.json` only contains the word `test` inside `latest`, so it is production code and keeps reporting.
    assert key_files == ["src/config.json", "src/latest.json"]
    assert [(row["index"], row["paths"][0], row["rule"], row["suppressed"]) for row in built_in_rows] == [
        (0, "Tests/Fixtures/keys.json", _AWS_RULE, 1),
        (1, "examples/demo.json", _AWS_RULE, 1),
        (2, "src/test_login.py", _AWS_RULE, 1),
    ]
    # No audit row may carry matched value material (FAMILY-CONTRACT.md section 5).
    assert _SYNTHETIC_AWS_KEY not in json.dumps(built_in_rows)


# `summary` takes no --fail-on: it reports rather than gates.
@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(["analyse", "--fail-on", "none", "--no-config"], id="analyse"),
        pytest.param(["summary", "--no-config"], id="summary"),
    ],
)
def test_the_skip_is_counted_on_text(sample_key_project: Path, arguments: list[str]) -> None:
    """A text surface that applies the skip prints its count, in the family wording.

    Args:
        sample_key_project: Key files in test and production paths, already the working directory.
        arguments: The command and flags under test, before the scan target.
    """
    expected = f"builtInTestPath[examples/demo.json] {_AWS_RULE}: 1 ("

    result = CliRunner().invoke(main, [*arguments, str(sample_key_project)])

    assert result.exit_code == 0, result.output
    assert expected in result.stdout, f"{arguments[0]} text does not count the skip:\n{result.stdout}"
