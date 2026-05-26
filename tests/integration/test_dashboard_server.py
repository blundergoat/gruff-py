import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import pytest

from gruffpy.cli_dashboard import _DashboardCliRequest, build_initial_dashboard_state
from gruffpy.command.dashboard_server import DashboardState, create_dashboard_server
from gruffpy.config.exceptions import ConfigError

_EXPECTED_SHELL_SUBSTRINGS = (
    "gruff-py dashboard",
    "controls-toggle",
    "controls-panel",
    "report-frame",
    "Project root",
)
_EXPECTED_SCAN_SUBSTRINGS = (
    ".paper",
    "gruff-dashboard-meta",
    "gruff-py analyse --format html --fail-on none -- src",
)
_EXPECTED_INTERACTIVE_SCAN_SUBSTRINGS = (
    'class="finding-filters"',
    "--report-interactive",
)


def test_dashboard_server_health_shell_and_scan(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n")

    with _served_dashboard(tmp_path, ("src",)) as base_url:
        health = _fetch(base_url + "/health")
        shell = _fetch(base_url + "/")
        scan = _fetch(base_url + "/scan")
        interactive_scan = _fetch(base_url + "/scan?reportInteractive=1")

    assert health == "ok\n"
    assert _missing(shell, _EXPECTED_SHELL_SUBSTRINGS) == []
    assert _missing(scan, _EXPECTED_SCAN_SUBSTRINGS) == []
    assert _missing(interactive_scan, _EXPECTED_INTERACTIVE_SCAN_SUBSTRINGS) == []


def _missing(body: str, expected: tuple[str, ...]) -> list[str]:
    return [s for s in expected if s not in body]


def test_dashboard_scan_returns_error_html_for_invalid_project(tmp_path: Path):
    with _served_dashboard(tmp_path, ("src",)) as base_url:
        body = _fetch(base_url + "/scan?project=/no/such/project")

    assert "Project root is not an existing directory." in body
    assert "/no/such/project" in body


def _dashboard_request(
    *,
    project_root: Path,
    fail_on: str = "none",
    was_fail_on_set_on_cli: bool = False,
    config_path: Path | None = None,
    should_skip_config: bool = False,
) -> _DashboardCliRequest:
    return _DashboardCliRequest(
        paths=(".",),
        project_root=project_root,
        host="127.0.0.1",
        port=0,
        fail_on=fail_on,
        was_fail_on_set_on_cli=was_fail_on_set_on_cli,
        config_path=config_path,
        should_skip_config=should_skip_config,
        should_include_ignored=False,
        should_render_interactive=False,
    )


def test_dashboard_initial_state_uses_config_minimum_severity_when_no_cli_flag(
    tmp_path: Path,
) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  dashboard: error\n"
    )
    request = _dashboard_request(project_root=tmp_path)

    state = build_initial_dashboard_state(request, tmp_path)

    assert state.fail_on == "error"


def test_dashboard_initial_state_falls_back_to_none_when_config_lacks_dashboard_key(
    tmp_path: Path,
) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  analyse: error\n"
    )
    request = _dashboard_request(project_root=tmp_path)

    state = build_initial_dashboard_state(request, tmp_path)

    assert state.fail_on == "none"


def test_dashboard_initial_state_respects_explicit_cli_fail_on_over_config(
    tmp_path: Path,
) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  dashboard: error\n"
    )
    request = _dashboard_request(
        project_root=tmp_path,
        fail_on="warning",
        was_fail_on_set_on_cli=True,
    )

    state = build_initial_dashboard_state(request, tmp_path)

    assert state.fail_on == "warning"


def test_dashboard_initial_state_skips_config_when_no_config_flag_set(
    tmp_path: Path,
) -> None:
    (tmp_path / ".gruff-py.yaml").write_text(
        "schemaVersion: gruff-py.config.v0.1\nminimumSeverity:\n  dashboard: error\n"
    )
    request = _dashboard_request(project_root=tmp_path, should_skip_config=True)

    state = build_initial_dashboard_state(request, tmp_path)

    assert state.fail_on == "none"


def test_dashboard_initial_state_surfaces_config_errors_at_startup(
    tmp_path: Path,
) -> None:
    (tmp_path / ".gruff-py.yaml").write_text("minimumSeverity:\n  dashboard: error\n")
    request = _dashboard_request(project_root=tmp_path)

    with pytest.raises(ConfigError, match="schemaVersion"):
        build_initial_dashboard_state(request, tmp_path)


@contextmanager
def _served_dashboard(project_root: Path, paths: tuple[str, ...]) -> Iterator[str]:
    server = create_dashboard_server(
        host="127.0.0.1",
        port=0,
        launch_root=project_root,
        initial_state=DashboardState(
            project=str(project_root),
            paths=" ".join(paths),
        ),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _base_url(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _base_url(server: ThreadingHTTPServer) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def _fetch(url: str) -> str:
    with urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")
