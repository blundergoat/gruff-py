import shlex
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from gruff.analysis.runner import run_analysis
from gruff.command.dashboard_page_renderer import DashboardPageRenderer
from gruff.finding.fail_threshold import FailThreshold
from gruff.finding.output_format import OutputFormat
from gruff.reporting.finding_display_filter import FindingDisplayFilter
from gruff.reporting.html_reporter import HtmlReporter


@dataclass(frozen=True, slots=True)
class DashboardState:
    project: str
    paths: str
    fail_on: str = "none"
    config: str = ""
    no_config: bool = False
    include_ignored: bool = False
    report_interactive: bool = False

    def to_query(self) -> dict[str, str]:
        return {
            "project": self.project,
            "paths": self.paths,
            "failOn": self.fail_on,
            "config": self.config,
            "noConfig": "1" if self.no_config else "0",
            "includeIgnored": "1" if self.include_ignored else "0",
            "reportInteractive": "1" if self.report_interactive else "0",
        }

    def merge_query(self, query: dict[str, str]) -> "DashboardState":
        return DashboardState(
            project=query.get("project", self.project),
            paths=query.get("paths", self.paths),
            fail_on=_valid_fail_on(query.get("failOn", self.fail_on)),
            config=query.get("config", self.config),
            no_config=_query_bool(query.get("noConfig", self.to_query()["noConfig"])),
            include_ignored=_query_bool(
                query.get("includeIgnored", self.to_query()["includeIgnored"])
            ),
            report_interactive=_query_bool(
                query.get("reportInteractive", self.to_query()["reportInteractive"])
            ),
        )


class _DashboardHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True


def create_dashboard_server(
    *,
    host: str,
    port: int,
    launch_root: Path,
    initial_state: DashboardState,
    renderer: DashboardPageRenderer | None = None,
) -> ThreadingHTTPServer:
    page_renderer = renderer or DashboardPageRenderer()
    launch_root = launch_root.resolve()

    class DashboardRequestHandler(BaseHTTPRequestHandler):
        server_version = "gruff-dashboard/0.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = _flatten_query(parse_qs(parsed.query, keep_blank_values=True))
            if parsed.path == "/health":
                self._send(HTTPStatus.OK, "text/plain; charset=utf-8", b"ok\n")
                return
            if parsed.path == "/favicon.ico":
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()
                return
            if parsed.path == "/":
                state = initial_state.merge_query(query)
                self._send_html(page_renderer.dashboard_html(state.to_query()))
                return
            if parsed.path == "/scan":
                self._send_html(_scan_html(page_renderer, launch_root, initial_state, query))
                return
            self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found\n")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_html(self, body: str) -> None:
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", body.encode("utf-8"))

        def _send(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return _DashboardHttpServer((host, port), DashboardRequestHandler)


def _scan_html(
    renderer: DashboardPageRenderer,
    launch_root: Path,
    initial_state: DashboardState,
    query: dict[str, str],
) -> str:
    started_at = time.perf_counter()
    state = initial_state.merge_query(query)
    scan_root = _resolve_project_root(state.project, launch_root)
    if scan_root is None:
        return renderer.error_html(
            "Project root is not an existing directory.",
            f"Project: {state.project}",
            exit_code=2,
            duration_ms=_duration_ms(started_at),
        )

    paths = _parse_paths(state.paths)
    config_path = _config_path(state.config, scan_root, state.no_config)
    command = _display_command_for(state, paths)
    try:
        report = run_analysis(
            paths=tuple(paths),
            config_path=config_path,
            no_config=state.no_config,
            output=OutputFormat.HTML,
            fail_threshold=FailThreshold(state.fail_on),
            include_ignored=state.include_ignored,
            project_root=scan_root,
            display_filter=FindingDisplayFilter(),
        )
        html_text = HtmlReporter(
            str(scan_root),
            editor_link="none",
            interactive=state.report_interactive,
        ).render(report)
        duration_ms = _duration_ms(started_at)
        return renderer.inject_dashboard_metadata(
            html_text,
            project_root=str(scan_root),
            command=command,
            exit_code=report.exit_code,
            duration_ms=duration_ms,
        )
    except Exception as exc:  # pragma: no cover - defensive iframe error path.
        return renderer.error_html(
            "The scan failed before an HTML report could be rendered.",
            str(exc),
            exit_code=2,
            duration_ms=_duration_ms(started_at),
        )


def _flatten_query(values: dict[str, list[str]]) -> dict[str, str]:
    return {key: items[-1] if items else "" for key, items in values.items()}


def _query_bool(value: str) -> bool:
    return value in {"1", "true", "yes", "on"}


def _valid_fail_on(value: str) -> str:
    return value if value in {item.value for item in FailThreshold} else "none"


def _resolve_project_root(project: str, launch_root: Path) -> Path | None:
    candidate = Path(project)
    if not candidate.is_absolute():
        candidate = launch_root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _parse_paths(paths: str) -> list[str]:
    try:
        parts = shlex.split(paths)
    except ValueError:
        parts = paths.split()
    result = [part for part in parts if part and not part.startswith("-")]
    return result or ["."]


def _config_path(config: str, project_root: Path, no_config: bool) -> Path | None:
    if no_config or config == "":
        return None
    path = Path(config)
    return path if path.is_absolute() else project_root / path


def _display_command_for(state: DashboardState, paths: list[str]) -> list[str]:
    command = ["gruff", "analyse", "--format", "html", "--fail-on", state.fail_on]
    if state.no_config:
        command.append("--no-config")
    elif state.config != "":
        command.extend(["--config", state.config])
    if state.include_ignored:
        command.append("--include-ignored")
    if state.report_interactive:
        command.append("--report-interactive")
    command.append("--")
    command.extend(paths)
    return command


def _duration_ms(started_at: float) -> int:
    return max(0, int(round((time.perf_counter() - started_at) * 1000)))
