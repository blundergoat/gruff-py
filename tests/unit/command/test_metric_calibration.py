import json
from pathlib import Path

import pytest

from gruffpy.command.metric_calibration import (
    build_metric_calibration_report,
    metric_calibration_payload,
    render_metric_calibration_text,
)

_TWO_FUNCTION_SAMPLE = (
    "def simple(value):\n"
    "    return value\n"
    "\n"
    "def branchy(value):\n"
    "    if value > 0 and value < 10:\n"
    "        return value + 1\n"
    "    return value - 1\n"
)


def _two_function_report(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text(_TWO_FUNCTION_SAMPLE)
    return build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )


@pytest.fixture
def two_function_payload(tmp_path: Path) -> dict[str, object]:
    """Return ``metric_calibration_payload`` for a 2-function sample project."""
    return metric_calibration_payload(_two_function_report(tmp_path), top=1)


def test_metric_calibration_report_counts_files_and_functions(tmp_path: Path) -> None:
    report = _two_function_report(tmp_path)
    assert (
        report.files_discovered,
        report.files_parsed,
        report.function_count,
        report.has_input_errors(),
    ) == (1, 1, 2, False)


def test_metric_calibration_payload_cyclomatic_distribution(
    two_function_payload: dict[str, object],
) -> None:
    metrics = {m["name"]: m for m in two_function_payload["metrics"]}  # type: ignore[index]
    cyclomatic = metrics["cyclomatic"]
    assert (cyclomatic["min"], cyclomatic["p50"], cyclomatic["p99"], cyclomatic["max"]) == (
        1,
        2,
        2.98,
        3,
    )


def test_metric_calibration_payload_npath_count(
    two_function_payload: dict[str, object],
) -> None:
    metrics = {m["name"]: m for m in two_function_payload["metrics"]}  # type: ignore[index]
    assert metrics["npath"]["count"] == 2


def test_metric_calibration_payload_collapses_single_threshold_rules(
    two_function_payload: dict[str, object],
) -> None:
    metrics = {m["name"]: m for m in two_function_payload["metrics"]}  # type: ignore[index]
    hv = metrics["halsteadVolume"]
    assert hv["threshold"] == 180
    assert hv["thresholdSeverity"] == "warning"
    assert "warningThreshold" not in hv
    assert "errorThreshold" not in hv


def test_metric_calibration_payload_maintainability_uses_below_direction(
    two_function_payload: dict[str, object],
) -> None:
    metrics = {m["name"]: m for m in two_function_payload["metrics"]}  # type: ignore[index]
    assert metrics["maintainabilityIndex"]["thresholdDirection"] == "below"


def test_metric_calibration_payload_top_cyclomatic_names_branchy(
    two_function_payload: dict[str, object],
) -> None:
    top = two_function_payload["top"]  # type: ignore[index]
    assert top["cyclomatic"][0]["symbol"] == "branchy"  # type: ignore[index]


def test_metric_calibration_text_is_human_readable(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def only():\n    return 1\n")

    report = build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )

    rendered = render_metric_calibration_text(report, top=1)

    assert "metric calibration" in rendered
    assert "Metric distributions:" in rendered
    assert "p99" in rendered
    assert "Top cyclomatic:" in rendered
    assert "src/sample.py:1 only cyclomatic=1" in rendered


def test_metric_calibration_payload_is_json_serialisable(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "sample.py").write_text("def only():\n    return 1\n")

    report = build_metric_calibration_report(
        paths=("src",),
        config_path=None,
        no_config=True,
        include_ignored=False,
        project_root=tmp_path,
    )

    encoded = json.dumps(metric_calibration_payload(report, top=1))

    assert "gruff-py.metric-calibration.v1" in encoded
