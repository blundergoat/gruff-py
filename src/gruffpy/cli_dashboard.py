"""Translate dashboard launch choices into safe browser startup state.

The CLI uses these helpers to seed the first scan form and prevent accidental
remote exposure before opening the local HTTP dashboard.
"""

import shlex
from dataclasses import dataclass
from pathlib import Path

import click

from gruffpy.command.dashboard_server import DashboardState
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_LOOPBACK_DASHBOARD_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True, slots=True)
class _DashboardCliRequest:
    """Carry the user's validated dashboard choices into server startup.

    Use this request after Click parsing so form defaults and bind protection
    share the exact project, host, and acknowledgment the user selected.
    """

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
    # False keeps existing callers fail-closed until a user explicitly opts in.
    has_acknowledged_public_bind: bool = False


def remote_dashboard_bind_warning(
    dashboard_host: str,
    has_acknowledged_public_bind: bool,
) -> str | None:
    """Refuse accidental remote exposure and describe an acknowledged public bind.

    Call before server startup so terminal users make the exposure decision
    before the unauthenticated browser dashboard becomes reachable.

    Args:
        dashboard_host: Non-empty host the user asked the dashboard to bind.
        has_acknowledged_public_bind: Whether the user passed ``--allow-public``.

    Returns:
        Remote-exposure warning for an acknowledged public bind, or None when
        the host is loopback and the user's local-only journey stays unchanged.

    Raises:
        click.ClickException: The user selected a non-loopback host without
            acknowledging that remote users could scan readable directories.
    """
    normalized_dashboard_host = dashboard_host.casefold()

    # A loopback choice keeps the dashboard local, so the user needs no warning.
    if normalized_dashboard_host in _LOOPBACK_DASHBOARD_HOSTS:
        return None

    # A remote bind without the flag is likely an accidental dashboard exposure.
    if not has_acknowledged_public_bind:
        raise click.ClickException(
            "Refusing to bind the unauthenticated dashboard to non-loopback host "
            f'"{dashboard_host}". Pass --allow-public to acknowledge that remote '
            "users can scan any directory readable by this process."
        )

    return (
        f"WARNING: binding dashboard to non-loopback host {dashboard_host}; remote "
        "users can access the unauthenticated dashboard and scan any directory "
        "readable by this process."
    )


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
    selected_fail_threshold = request.fail_on
    # An omitted CLI threshold lets the opening form inherit the user's project setting.
    if not request.was_fail_on_set_on_cli and not request.should_skip_config:
        configured_fail_threshold = _resolve_config_dashboard_fail_on(request.config_path, project)
        # A configured value replaces the generic Click default shown in the form.
        if configured_fail_threshold is not None:
            selected_fail_threshold = configured_fail_threshold
    # No paths means scan the project root; no config means use normal discovery.
    return DashboardState(
        project=str(project),
        paths=" ".join(shlex.quote(path) for path in (request.paths or (".",))),
        fail_on=selected_fail_threshold,
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
    # A relative config was chosen from the project, not the launch directory.
    if config_path is not None and not config_path.is_absolute():
        config_path = project / config_path
    rule_registry = RuleRegistry.defaults()
    default_analysis_config = AnalysisConfig.from_registry(rule_registry)
    loaded_analysis_config, _ = ConfigLoader(project, default_analysis_config).load(config_path)
    configured_dashboard_threshold = loaded_analysis_config.minimum_severity.get("dashboard")
    # No dashboard key means the form keeps its CLI default instead of showing empty input.
    return (
        configured_dashboard_threshold.value if configured_dashboard_threshold is not None else None
    )
