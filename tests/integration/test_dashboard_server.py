import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from gruffpy.command.dashboard_server import DashboardState, create_dashboard_server


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
    assert "gruff-py dashboard" in shell
    assert "controls-toggle" in shell
    assert "controls-panel" in shell
    assert "report-frame" in shell
    assert "Project root" in shell
    assert ".paper" in scan
    assert "gruff-dashboard-meta" in scan
    assert "gruff-py analyse --format html --fail-on none -- src" in scan
    assert 'class="finding-filters"' in interactive_scan
    assert "--report-interactive" in interactive_scan


def test_dashboard_scan_returns_error_html_for_invalid_project(tmp_path: Path):
    with _served_dashboard(tmp_path, ("src",)) as base_url:
        body = _fetch(base_url + "/scan?project=/no/such/project")

    assert "Project root is not an existing directory." in body
    assert "/no/such/project" in body


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
