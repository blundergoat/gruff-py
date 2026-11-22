"""Smoke test for ``scripts/test-performance.sh``.

Runs the script in --quick mode and asserts that it exits 0 and emits a
JSON document with the expected top-level keys. Skipped on non-Linux hosts
and when ``bash`` is unavailable.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "test-performance.sh"


pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="perf script smoke test is Linux-only"),
    pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH"),
]


def _run_perf_script_quick(json_out: Path, output_dir: Path) -> subprocess.CompletedProcess:
    """Run the quick performance suite from the temporary output directory's parent.

    Args:
        json_out: File that receives the script's JSON results.
        output_dir: Directory that receives the script's other output.

    Returns:
        The completed process with captured text output; a non-zero exit does not raise.

    Raises:
        subprocess.TimeoutExpired: The script runs for more than 300 seconds.
    """
    return subprocess.run(
        [
            "bash",
            str(SCRIPT_PATH),
            "--quick",
            "--repeat",
            "3",
            "--json",
            json_out.name,
            "--output-dir",
            output_dir.name,
        ],
        cwd=json_out.parent,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=300,
        check=False,
    )


@pytest.fixture(scope="module")
def quick_run_payload(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """Run the perf script once at --quick mode and return its parsed JSON payload.

    Args:
        tmp_path_factory: Pytest-provided factory for module-scoped temp dirs.

    Returns:
        The parsed ``--json`` payload from a single ``--quick`` invocation.
    """
    tmp_path = tmp_path_factory.mktemp("perf_quick")
    json_out = tmp_path / "perf-results.json"
    proc = _run_perf_script_quick(json_out, tmp_path / "perf-out")
    assert proc.returncode == 0, f"perf script exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert json_out.exists(), "expected JSON output file was not written"
    return json.loads(json_out.read_text())


_EXPECTED_TOP_LEVEL_KEYS = {
    "schemaVersion",
    "host",
    "source",
    "repeat",
    "workloads",
    "perRuleCost",
    "importTime",
    "regressions",
}


def test_perf_script_payload_advertises_schema_version_1(
    quick_run_payload: dict[str, object],
) -> None:
    """Report ``schemaVersion`` 1 in the quick run's JSON payload.

    Args:
        quick_run_payload: Parsed payload from the module's single quick run, read for its schema version.

    Returns:
        None. Checks the schema version in the quick-run payload.
    """
    assert quick_run_payload.get("schemaVersion") == 1


def test_perf_script_payload_publishes_documented_top_level_keys(
    quick_run_payload: dict[str, object],
) -> None:
    """Include every documented top-level key in the quick run's JSON payload.

    Args:
        quick_run_payload: Parsed payload from the module's single quick run, checked for the expected keys.

    Returns:
        None. Checks for the expected top-level keys and lists any missing keys if the assertion fails.
    """
    assert _EXPECTED_TOP_LEVEL_KEYS.issubset(quick_run_payload), f"missing top-level keys: {_EXPECTED_TOP_LEVEL_KEYS - quick_run_payload.keys()}"


def test_perf_script_payload_reports_cold_start_and_analyse_workloads(
    quick_run_payload: dict[str, object],
) -> None:
    """Report the ``cold-start`` and ``analyse-src-text`` workloads in the quick run's payload.

    Args:
        quick_run_payload: Parsed payload whose workload names are collected.

    Returns:
        None. Checks that both expected workload names appear in the quick-run payload.
    """
    workloads = quick_run_payload["workloads"]
    workload_names = {w["name"] for w in workloads}
    assert {"cold-start", "analyse-src-text"}.issubset(workload_names)


_GIT_COMMIT_LENGTH = 40
_DIGEST_LENGTH = 64


def _section(payload: dict[str, object], *keys: str) -> dict[str, object]:
    """Read one nested section of the perf payload, so a shape change fails here rather than later.

    Args:
        payload: Perf payload or subsection where the key lookup starts.
        keys: Section names to walk, outermost first.

    Returns:
        The addressed section, or payload itself when no keys are supplied.
    """
    section: object = payload
    for key in keys:
        assert isinstance(section, dict), keys
        section = section[key]
    assert isinstance(section, dict), keys
    return section


def test_perf_script_payload_describes_its_host(
    quick_run_payload: dict[str, object],
) -> None:
    """Record the platform, uname and CPU in the quick run's host metadata.

    Args:
        quick_run_payload: Parsed payload from one quick perf run.

    Returns:
        None. Checks that all three host fields contain values.
    """
    host = _section(quick_run_payload, "host")

    assert host["platform"]
    assert host["uname"]
    assert host["cpu"]


def test_perf_script_payload_binds_its_runtime_source(
    quick_run_payload: dict[str, object],
) -> None:
    """Require source metadata with revision and digest lengths, a dirty flag and the expected runtime paths.

    Args:
        quick_run_payload: Parsed payload from one quick perf run.

    Returns:
        None. Checks the revision metadata, included runtime paths, file count and digest length.
    """
    source = _section(quick_run_payload, "source")
    runtime_source = _section(source, "runtimeSource")

    assert len(source["gitCommit"]) == _GIT_COMMIT_LENGTH
    assert isinstance(source["gitDirty"], bool)
    assert set(runtime_source["includedPaths"]) == {
        "src",
        "tests",
        ".gitignore",
        ".gruff-py.yaml",
        ".gruff.yaml",
        "gruff-baseline.json",
        "pyproject.toml",
        "uv.lock",
    }
    assert runtime_source["fileCount"] > 0
    assert len(runtime_source["digest"]) == _DIGEST_LENGTH


def test_perf_script_workloads_have_well_formed_timing_record(
    quick_run_payload: dict[str, object],
) -> None:
    """Give every workload a command list, an integer exit code and a positive median between its minimum and maximum.

    Args:
        quick_run_payload: Parsed payload whose workload timing records are checked.

    Returns:
        None. Checks command, exit code and timing fields for each workload in the payload.
    """
    workloads = quick_run_payload["workloads"]
    assert all(
        isinstance(w["command"], list) and isinstance(w["exitCode"], int) and w["median"] > 0 and w["min"] <= w["median"] <= w["max"]
        for w in workloads
    ), workloads


def test_perf_script_cold_start_workload_exits_zero(
    quick_run_payload: dict[str, object],
) -> None:
    """Check the recorded exit code for the quick run's cold-start workload.

    Args:
        quick_run_payload: Parsed payload that must contain the ``cold-start`` workload.

    Returns:
        None. Asserts that the cold-start workload recorded exit code 0.
    """
    workloads = quick_run_payload["workloads"]
    cold_start = next(w for w in workloads if w["name"] == "cold-start")
    assert cold_start["exitCode"] == 0


def test_perf_script_baseline_regression_exits_one(tmp_path: Path) -> None:
    """Exit 1 and print ``regressions detected`` when a quick run is compared with one-millisecond baseline medians.

    The environment sets the regression thresholds to one millisecond and one percent.

    Args:
        tmp_path: Holds the baseline JSON file and the script's output folder.

    Returns:
        None. Runs the perf script against the temporary baseline and checks its regression exit code and message.
    """
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "workloads": [
                    {"name": "cold-start", "median": 0.001},
                    {"name": "analyse-src-text", "median": 0.001},
                ],
            }
        )
    )

    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT_PATH),
            "--quick",
            "--repeat",
            "3",
            "--baseline",
            baseline.name,
            "--output-dir",
            "perf-out",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PERF_REGRESSION_ABS_S": "0.001",
            "PERF_REGRESSION_PCT": "1",
        },
        timeout=300,
        check=False,
    )

    assert proc.returncode == 1, f"expected regression exit 1\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "regressions detected" in proc.stdout


_DOCUMENTED_FLAGS = (
    "--quick",
    "--json",
    "--repeat",
    "--baseline",
    "--update-baseline",
    "--output-dir",
    "--scale",
)


def test_perf_script_help_lists_documented_flags() -> None:
    """List the expected flags in the perf script's ``--help`` output.

    Returns:
        None. Runs the script with --help and checks its standard output for the expected flags.
    """
    proc = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    missing = [flag for flag in _DOCUMENTED_FLAGS if flag not in proc.stdout]
    assert not missing, f"--help output missing flags: {missing}"
