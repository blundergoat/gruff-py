"""Cover ``FAMILY-CONTRACT.md`` section 13c as a user meets it: another tool's comment, and one call under two rules.

A bare bandit ``# nosec`` on the reported line or alone above it suppresses a security finding; one naming a test id,
a type-checker comment and an uncommented line keep reporting. zizmor's ``ignore[unpinned-uses]`` suppresses only its
own line's unpinned action. A dynamic ``__import__`` reports once, as ``security.dangerous-function-call``. Every
removal is counted in an ``inline`` or ``duplicate`` audit row, the text line and a suppressed SARIF result.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from gruffpy.cli import main
from gruffpy.suppression.inline_suppression_filter import DUPLICATE_REASON, INLINE_REASON

_LOADER = '''"""Fixture for section 13c."""

import pickle


def load(data: bytes, module_name: str) -> object:
    """Load data and a module."""
    first = pickle.loads(data)  # nosec
    second = pickle.loads(data)  # nosec B301
    # nosec
    third = pickle.loads(data)
    fourth = pickle.loads(data)  # type: ignore
    fifth = pickle.loads(data)  # nosec assert_used
    print(first, second, third, fourth, fifth)
    return __import__(module_name)
'''

_WORKFLOW = """name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3 # zizmor: ignore[unpinned-uses]
      - uses: docker/build-push-action@v6
"""

# Lines the fixture reports on: the second action, a ``# nosec`` naming B301, a ``# type: ignore``, and ``__import__``.
_UNPINNED_ACTION_LINE = _WORKFLOW.splitlines().index("      - uses: docker/build-push-action@v6") + 1
_NAMED_TEST_ID_LINE = _LOADER.splitlines().index("    second = pickle.loads(data)  # nosec B301") + 1
_NAMED_TEST_NAME_LINE = _LOADER.splitlines().index("    fifth = pickle.loads(data)  # nosec assert_used") + 1
_TYPE_IGNORE_LINE = _LOADER.splitlines().index("    fourth = pickle.loads(data)  # type: ignore") + 1
_IMPORT_LINE = _LOADER.splitlines().index("    return __import__(module_name)") + 1


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write the fixture project and run from its root, as a user would.

    Args:
        tmp_path: Empty directory pytest provides for the project.
        monkeypatch: Moves the working directory to the project for the test.

    Returns:
        The project root.
    """
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "loader.py").write_text(_LOADER)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(_WORKFLOW)
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nrules:\n"
        "  security.dangerous-function-call:\n    enabled: true\n"
        "  security.unsafe-pickle:\n    enabled: true\n"
        "  security.variable-import:\n    enabled: true\n"
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _analyse(output_format: str) -> str:
    """Run ``analyse`` over the project in one format.

    Args:
        output_format: Format name passed to ``--format``.

    Returns:
        The command's standard output.
    """
    arguments = ["analyse", ".", "--format", output_format, "--fail-on", "none", "--config", ".gruff-py.yaml", "--no-baseline", "--include-ignored"]
    result = CliRunner().invoke(main, arguments)
    assert result.exit_code == 0, result.output
    return result.stdout


@pytest.mark.usefixtures("project")
def test_comments_suppress_only_what_they_name_and_an_import_reports_once() -> None:
    payload: dict[str, Any] = json.loads(_analyse("json"))

    security = [(finding["file"], finding["line"], finding["ruleId"]) for finding in payload["findings"] if finding["ruleId"].startswith("security.")]
    assert security == [
        (".github/workflows/ci.yml", _UNPINNED_ACTION_LINE, "security.github-actions-unpinned-action"),
        ("app/loader.py", _NAMED_TEST_ID_LINE, "security.unsafe-pickle"),
        ("app/loader.py", _TYPE_IGNORE_LINE, "security.unsafe-pickle"),
        ("app/loader.py", _NAMED_TEST_NAME_LINE, "security.unsafe-pickle"),
        ("app/loader.py", _IMPORT_LINE, "security.dangerous-function-call"),
    ]
    rows = [(row["index"], row["source"], row["paths"], row["rule"], row["suppressed"], row["reason"]) for row in payload["suppressions"]]
    assert rows == [
        (0, "inline", [".github/workflows/ci.yml"], "security.github-actions-unpinned-action", 1, INLINE_REASON),
        (1, "inline", ["app/loader.py"], "security.unsafe-pickle", 2, INLINE_REASON),
        (2, "duplicate", ["app/loader.py"], "security.variable-import", 1, DUPLICATE_REASON),
    ]


@pytest.mark.usefixtures("project")
def test_text_and_sarif_keep_every_removal_visible() -> None:
    text = _analyse("text")
    assert f"inline[app/loader.py] security.unsafe-pickle: 2 ({INLINE_REASON})" in text
    assert f"duplicate[app/loader.py] security.variable-import: 1 ({DUPLICATE_REASON})" in text

    results = json.loads(_analyse("sarif"))["runs"][0]["results"]
    suppressions = [result["suppressions"] for result in results if "suppressions" in result]
    assert suppressions == [
        [{"kind": "inSource", "justification": INLINE_REASON}],
        [{"kind": "inSource", "justification": INLINE_REASON}],
        [{"kind": "inSource", "justification": INLINE_REASON}],
        [{"kind": "inSource", "justification": DUPLICATE_REASON}],
    ]
