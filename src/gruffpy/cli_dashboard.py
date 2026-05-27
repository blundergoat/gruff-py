"""Dashboard CLI helpers: request dataclass and config-aware initial state factory."""

import shlex
from dataclasses import dataclass
from pathlib import Path

from gruffpy.command.dashboard_server import DashboardState
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry


@dataclass(frozen=True, slots=True)
class _DashboardCliRequest:
    """Bundle of validated ``dashboard`` CLI flags before the server is started."""

    paths: tuple[str, ...]
    project_root: Path | None
    host: str
    port: int
    fail_on: str
    was_fail_on_set_on_cli: bool
    config_path: Path | None
    should_skip_config: bool
    should_include_ignored: bool
    should_render_interactive: bool


def build_initial_dashboard_state(request: _DashboardCliRequest, project: Path) -> DashboardState:
    """Build the seed ``DashboardState`` with the precedence rule applied.

    Precedence (ADR-019): CLI ``--fail-on`` flag > ``minimumSeverity.dashboard``
    in the loaded config > Click default. Config-load errors propagate so the
    user sees them at dashboard startup rather than on the first scan.

    Args:
        request: Validated dashboard CLI request (paths, fail_on, config path).
        project: Resolved project root used as the config-discovery base.

    Returns:
        The initial dashboard form state with the precedence-resolved ``fail_on``
        and all other request fields threaded through.
    """
    fail_on = request.fail_on
    if not request.was_fail_on_set_on_cli and not request.should_skip_config:
        configured = _resolve_config_dashboard_fail_on(request.config_path, project)
        if configured is not None:
            fail_on = configured
    return DashboardState(
        project=str(project),
        paths=" ".join(shlex.quote(path) for path in (request.paths or (".",))),
        fail_on=fail_on,
        config=str(request.config_path) if request.config_path is not None else "",
        no_config=request.should_skip_config,
        include_ignored=request.should_include_ignored,
        report_interactive=request.should_render_interactive,
    )


def _resolve_config_dashboard_fail_on(config_path: Path | None, project: Path) -> str | None:
    """Return ``config.minimum_severity['dashboard'].value`` or ``None`` if absent.

    Mirrors ``dashboard_server._config_path`` by resolving a relative *config_path*
    against the dashboard *project* root, so the initial form seed reads the same
    file that ``/scan`` will read at run time. Without this normalisation a
    relative ``--config`` resolves against the launch CWD and diverges from the
    scan path when ``--project <dir>`` is invoked from elsewhere.
    """
    if config_path is not None and not config_path.is_absolute():
        config_path = project / config_path
    registry = RuleRegistry.defaults()
    defaults = AnalysisConfig.from_registry(registry)
    config, _ = ConfigLoader(project, defaults).load(config_path)
    configured = config.minimum_severity.get("dashboard")
    return configured.value if configured is not None else None
