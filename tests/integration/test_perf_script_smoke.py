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


def test_perf_script_quick_mode_smoke(tmp_path: Path) -> None:
    json_out = tmp_path / "perf-results.json"
    output_dir = tmp_path / "perf-out"

    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT_PATH),
            "--quick",
            "--repeat",
            "3",
            "--json",
            str(json_out),
            "--output-dir",
            str(output_dir),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=300,
        check=False,
    )

    assert proc.returncode == 0, (
        f"perf script exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert json_out.exists(), "expected JSON output file was not written"

    payload = json.loads(json_out.read_text())
    assert payload["schemaVersion"] == 1
    for key in ("host", "repeat", "workloads", "perRuleCost", "importTime", "regressions"):
        assert key in payload, f"missing top-level key: {key}"

    workload_names = {w["name"] for w in payload["workloads"]}
    assert {"cold-start", "analyse-src-text"}.issubset(workload_names)

    for workload in payload["workloads"]:
        assert workload["median"] > 0
        assert workload["min"] <= workload["median"] <= workload["max"]


def test_perf_script_help_lists_documented_flags() -> None:
    proc = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    for flag in ("--quick", "--json", "--repeat", "--baseline", "--update-baseline"):
        assert flag in proc.stdout, f"--help output missing {flag}"
