"""Translate dashboard launch choices into safe browser startup state.

The CLI uses these helpers to seed the first scan form and prevent accidental
remote exposure before opening the local HTTP dashboard.
"""

import ipaddress
import shlex
from dataclasses import dataclass
from pathlib import Path

import click

from gruffpy.command.dashboard_server import DashboardState
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.registry import RuleRegistry

_LOOPBACK_DASHBOARD_HOST_NAMES = frozenset({"localhost"})


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
    deep_scan_budget: str = ""
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
        dashboard_host: Requested bind host. An empty value is treated as non-loopback.
        has_acknowledged_public_bind: Whether the user passed ``--allow-public``.

    Returns:
        Exposure warning for an acknowledged non-loopback bind, or None when a loopback bind needs no warning.

    Raises:
        click.ClickException: The user selected a non-loopback host without
            acknowledging that remote users could scan readable directories.
    """
    # A loopback choice keeps the dashboard local, so the user needs no warning.
    if _is_loopback_dashboard_host(dashboard_host):
        return None

    # An unacknowledged non-loopback bind stops startup before the dashboard can be reached.
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


def _is_loopback_dashboard_host(dashboard_host: str) -> bool:
    """Decide whether a host keeps the dashboard reachable only from this machine.

    Call from the bind guard to spare users binding a loopback address from acknowledging remote exposure.

    Args:
        dashboard_host: Host the user typed; an unparsable value is treated as remote.

    Returns:
        True for localhost or a loopback IP, including the full 127.0.0.0/8 range. False sends the user through the acknowledgment gate.
    """
    normalized_dashboard_host = dashboard_host.casefold()
    # A named host resolves at bind time, so only the documented local name is trusted here.
    if normalized_dashboard_host in _LOOPBACK_DASHBOARD_HOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(normalized_dashboard_host).is_loopback
    # Leave the refusal or exposure warning to the bind guard when the host fails IP parsing.
    except ValueError:
        return False


def build_initial_dashboard_state(request: _DashboardCliRequest, project: Path) -> DashboardState:
    """Build the seed ``DashboardState`` with the precedence rule applied.

    A CLI threshold overrides failOn.dashboard, which overrides the Click default; configuration failures propagate during startup.

    Args:
        request: Validated dashboard CLI request (paths, fail_on, config path).
        project: Resolved project root used as the config-discovery base.

    Returns:
        The dashboard form fields, with the chosen threshold, shell-quoted paths, and an empty config value when no file was selected.
    """
    selected_fail_threshold = request.fail_on
    # An omitted CLI threshold lets the opening form inherit the user's project setting.
    if not request.was_fail_on_set_on_cli and not request.should_skip_config:
        configured_fail_threshold = _resolve_config_dashboard_fail_on(request.config_path, project)
        # A configured value replaces the generic Click default shown in the form.
        if configured_fail_threshold is not None:
            selected_fail_threshold = configured_fail_threshold
    # Empty paths seed a project-root scan; an absent config path leaves discovery to the no_config setting.
    return DashboardState(
        project=str(project),
        paths=" ".join(shlex.quote(path) for path in (request.paths or (".",))),
        fail_on=selected_fail_threshold,
        config=str(request.config_path) if request.config_path is not None else "",
        no_config=request.should_skip_config,
        include_ignored=request.should_include_ignored,
        report_interactive=request.should_render_interactive,
        deep_scan_budget=request.deep_scan_budget,
    )


def _resolve_config_dashboard_fail_on(config_path: Path | None, project: Path) -> str | None:
    """Load the dashboard threshold from the same project config used by later scans.

    Use while seeding the form; None keeps the CLI default visible.
    Project-relative resolution keeps startup and later scan settings aligned.

    Args:
        config_path: User-selected config; None asks normal project discovery to choose one.
        project: Dashboard project root used to resolve relative config paths and discover configuration.

    Returns:
        Configured threshold text, or None when the user has no dashboard-specific setting.
    """
    # A relative config was chosen from the project, not the launch directory.
    if config_path is not None and not config_path.is_absolute():
        config_path = project / config_path
    rule_registry = RuleRegistry.defaults()
    default_analysis_config = AnalysisConfig.from_registry(rule_registry)
    loaded_analysis_config, _ = ConfigLoader(project, default_analysis_config).load(config_path)
    configured_dashboard_threshold = loaded_analysis_config.minimum_severity.get("dashboard")
    # No dashboard key means the form keeps its CLI default instead of showing empty input.
    return configured_dashboard_threshold.value if configured_dashboard_threshold is not None else None
