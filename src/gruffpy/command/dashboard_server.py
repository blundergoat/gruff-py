"""Local HTTP server backing ``gruff-py dashboard`` - serves the shell and `/scan` results."""

import shlex
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.analysis.runner import run_analysis
from gruffpy.command.dashboard_page_renderer import DashboardPageRenderer
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.reporting.html_reporter import HtmlReporter
from gruffpy.version import TOOL_NAME


@dataclass(frozen=True, slots=True)
class DashboardState:
    """Immutable snapshot of dashboard form fields round-tripped through query strings.

    Attributes:
        project: Project root entered in the dashboard form.
        paths: Source paths entered in the dashboard form.
        fail_on: Failure threshold selected for dashboard scans.
        config: Optional configuration file path.
        no_config: Whether config loading is disabled.
        include_ignored: Whether ignored files are included in scans.
        report_interactive: Whether generated HTML reports keep interactive controls.
        deep_scan_budget: Atomic deep-scan override, or empty to use config/defaults.
    """

    project: str
    paths: str
    fail_on: str = "none"
    config: str = ""
    no_config: bool = False
    include_ignored: bool = False
    report_interactive: bool = False
    deep_scan_budget: str = ""

    def to_query(self) -> dict[str, str]:
        """Serialise the state to the dashboard URL query-string shape.

        Boolean fields become ``"1"``/``"0"`` strings so the same encoding
        survives both the form post-back and the URL bar.

        Returns:
            Camel-cased query parameters ready to be URL-encoded.
        """
        return {
            "project": self.project,
            "paths": self.paths,
            "failOn": self.fail_on,
            "config": self.config,
            "noConfig": "1" if self.no_config else "0",
            "includeIgnored": "1" if self.include_ignored else "0",
            "reportInteractive": "1" if self.report_interactive else "0",
            "deepScanBudget": self.deep_scan_budget,
        }

    def merge_query(self, query: dict[str, str]) -> "DashboardState":
        """Return a new ``DashboardState`` with *query* values layered over the current ones.

        Each query parameter overrides the corresponding state field; missing
        keys fall back to ``self``. The ``failOn`` value is sanitised against
        :class:`FailThreshold` to avoid blindly accepting URL input.

        Args:
            query: Query parameters parsed from the request (single value each).

        Returns:
            Merged state used for the scan.
        """
        return DashboardState(
            project=query.get("project", self.project),
            paths=query.get("paths", self.paths),
            fail_on=_valid_fail_on(query.get("failOn", self.fail_on)),
            config=query.get("config", self.config),
            no_config=_query_bool(query.get("noConfig", self.to_query()["noConfig"])),
            include_ignored=_query_bool(query.get("includeIgnored", self.to_query()["includeIgnored"])),
            report_interactive=_query_bool(query.get("reportInteractive", self.to_query()["reportInteractive"])),
            deep_scan_budget=query.get("deepScanBudget", self.deep_scan_budget),
        )


class _DashboardHttpServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` subclass that sets ``SO_REUSEADDR`` for fast restart in dev."""

    allow_reuse_address = True


def create_dashboard_server(
    *,
    host: str,
    port: int,
    launch_root: Path,
    initial_state: DashboardState,
    renderer: DashboardPageRenderer | None = None,
) -> ThreadingHTTPServer:
    """Build (but do not start) the threaded HTTP server backing the dashboard.

    Returns a ``ThreadingHTTPServer`` so the caller can manage the lifecycle
    (``serve_forever`` in the foreground, ``server_close`` on shutdown).
    The handler routes ``/`` to the shell, ``/scan`` to a single analyse
    run, ``/health`` to a probe, and ``/favicon.ico`` to ``204``.

    Args:
        host: Bind address for the listener.
        port: TCP port for the listener.
        launch_root: Directory the CLI was invoked from; used to resolve
            relative ``project`` paths from the form.
        initial_state: Seed state derived from the CLI flags.
        renderer: Page renderer override (tests inject a stub); defaults
            to a fresh :class:`DashboardPageRenderer`.

    Returns:
        Configured but not yet serving HTTP server.
    """
    page_renderer = renderer or DashboardPageRenderer()
    launch_root = launch_root.resolve()

    class DashboardRequestHandler(BaseHTTPRequestHandler):
        """Per-request handler dispatching the four dashboard routes: shell, scan, health, 404."""

        server_version = "gruff-dashboard/0.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler hook name
            """Route GET to shell, scan, health, or 404 (``BaseHTTPRequestHandler`` hook)."""
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
            """Silence ``BaseHTTPRequestHandler``'s default stderr access log.

            Args:
                format: Printf-style format from the base handler.
                args: Format arguments - discarded.
            """
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
    """Run one dashboard scan for the merged request state and return the HTML page the /scan route serves into the report iframe.

    The scan always runs with the baseline disabled and the default display filter, and the HTML report is rendered without editor links. A project
    root that resolves to a path that is not an existing directory, or an exception raised while running the analysis or rendering the report,
    produces a dashboard error page with exit code 2. A project value that path resolution rejects with ValueError, such as one containing a NUL
    character, is not caught and propagates.

    Args:
        renderer: Dashboard page renderer that builds error pages and injects scan metadata into the HTML report.
        launch_root: Resolved directory the dashboard was launched from; relative project values are resolved against it.
        initial_state: Seed dashboard state from the CLI flags; query values are layered over it before the scan.
        query: Flattened /scan query parameters, one value per key, that override the seed state.

    Returns:
        HTML for the iframe: the HTML report with the project root, display command, report exit code and duration injected as dashboard metadata, or
        a dashboard error page with exit code 2 when the project root is not an existing directory or the scan fails.
    """
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
            AnalysisRunRequest(
                paths=tuple(paths),
                config_path=config_path,
                no_config=state.no_config,
                output=OutputFormat.HTML,
                fail_threshold=FailThreshold(state.fail_on),
                include_ignored=state.include_ignored,
                project_root=scan_root,
                display_filter=FindingDisplayFilter(),
                baseline=BaselineOptions(disabled=True),
                deep_scan_budget=state.deep_scan_budget,
            )
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
    """Reduce parsed query parameters to one value per key, keeping the last value supplied for each key.

    Args:
        values: Query parameters from parse_qs, mapping each key to every value it appeared with in the URL.

    Returns:
        Mapping of each key to its last value, or to the empty string when the key has no values.
    """
    return {key: items[-1] if items else "" for key, items in values.items()}


def _query_bool(value: str) -> bool:
    """Interpret a dashboard query flag as true only for the exact values 1, true, yes or on.

    Args:
        value: Raw flag value from the query string, or the 1 or 0 encoding produced by DashboardState.to_query.

    Returns:
        True when value is exactly 1, true, yes or on (case-sensitive); False for any other value, including 0 and the empty string.
    """
    return value in {"1", "true", "yes", "on"}


def _valid_fail_on(value: str) -> str:
    """Keep a failOn value only when it matches a FailThreshold value, so URL input cannot select an unknown threshold.

    Args:
        value: failOn value taken from the query, or the current state's fail_on when the query omits it.

    Returns:
        value unchanged when it matches a FailThreshold value, otherwise the string none.
    """
    return value if value in {item.value for item in FailThreshold} else "none"


def _resolve_project_root(project: str, launch_root: Path) -> Path | None:
    """Resolve the dashboard project field to an existing directory, interpreting relative values against the launch root.

    Args:
        project: Project root text from the dashboard state; a relative value is joined to launch_root, so an empty value resolves to launch_root
            itself.
        launch_root: Directory that relative project values are resolved against.

    Returns:
        The resolved absolute path when it is an existing directory; None when path resolution raises OSError or the resolved path is not a directory.
    """
    candidate = Path(project)
    if not candidate.is_absolute():
        candidate = launch_root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _parse_paths(paths: str) -> list[str]:
    """Split the dashboard paths field into scan path arguments, dropping anything that looks like a command-line option.

    Shell-style quoting is honoured; text that shlex cannot split, such as an unclosed quote or a trailing backslash, falls back to plain whitespace
    splitting.

    Args:
        paths: Raw paths text from the dashboard state.

    Returns:
        Path arguments with empty parts and parts starting with - removed, or a list holding only . when no path remains.
    """
    try:
        parts = shlex.split(paths)
    except ValueError:
        parts = paths.split()
    result = [part for part in parts if part and not part.startswith("-")]
    return result or ["."]


def _config_path(config: str, project_root: Path, no_config: bool) -> Path | None:
    """Work out the explicit config file path a dashboard scan passes to analysis, anchoring relative paths at the project root.

    Args:
        config: Config path text from the dashboard state; empty means no explicit config path.
        project_root: Resolved project root that a relative config path is joined to.
        no_config: When true, config loading is disabled and config is ignored.

    Returns:
        None when no_config is true or config is empty; otherwise config as given when absolute, or joined to project_root when relative.
    """
    if no_config or config == "":
        return None
    path = Path(config)
    return path if path.is_absolute() else project_root / path


def _display_command_for(state: DashboardState, paths: list[str]) -> list[str]:
    """Build the analyse argv that the dashboard displays as the command line for a scan.

    The argv always carries --format html and --fail-on, then --no-config or --config (no_config wins over config), --include-ignored,
    --report-interactive and --deep-scan-budget only when set, then -- followed by the paths. It is display-only; the scan itself runs through
    run_analysis.

    Args:
        state: Merged dashboard state whose fail_on, config, no_config, include_ignored, report_interactive and deep_scan_budget fields select the
            flags.
        paths: Parsed scan paths appended after the -- separator.

    Returns:
        argv list beginning with the tool name and analyse and ending with -- and the paths; the dashboard renderer shell-quotes it for display.
    """
    command = [TOOL_NAME, "analyse", "--format", "html", "--fail-on", state.fail_on]
    if state.no_config:
        command.append("--no-config")
    elif state.config != "":
        command.extend(["--config", state.config])
    if state.include_ignored:
        command.append("--include-ignored")
    if state.report_interactive:
        command.append("--report-interactive")
    if state.deep_scan_budget:
        command.extend(["--deep-scan-budget", state.deep_scan_budget])
    command.append("--")
    command.extend(paths)
    return command


def _duration_ms(started_at: float) -> int:
    """Measure the wall-clock milliseconds elapsed since a scan started, for the scan metadata and error pages the dashboard renders.

    Args:
        started_at: time.perf_counter value taken when the scan began.

    Returns:
        Elapsed milliseconds rounded to the nearest integer, never negative.
    """
    return max(0, int(round((time.perf_counter() - started_at) * 1000)))
