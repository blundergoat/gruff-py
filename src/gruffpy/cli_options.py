"""Reusable Click option and command decorators shared by the CLI command tree."""

import inspect
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar, cast

import click

from gruffpy.analysis.baseline import DEFAULT_BASELINE_FILENAME
from gruffpy.cli_state import state as _state
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.severity import Severity
from gruffpy.version import TOOL_NAME, VERSION

_F = TypeVar("_F", bound=Callable[..., Any])
ClickDecorator = Callable[[Callable[..., Any]], Callable[..., Any]]
_command_root: click.Group | None = None


def bind_root_group(root: click.Group) -> None:
    """Register *root* as the parent Click group that ``@<command>_command`` decorators attach to.

    Must be called once during CLI bootstrap before any ``@analyse_command``
    / ``@dashboard_command`` / etc. decorator runs - otherwise ``_command``
    raises ``RuntimeError``.

    Args:
        root: Click root group that owns every gruff subcommand.
    """
    global _command_root
    _command_root = root


def apply_decorators(function: _F, decorators: Iterable[ClickDecorator]) -> _F:
    """Apply *decorators* to *function* in order, returning the wrapped callable.

    Iterates the iterable left-to-right: ``decorators = (a, b, c)`` produces
    ``c(b(a(function)))``. Used to compose the per-command decorator tuples
    declared at the bottom of this module.

    Args:
        function: The Click command function to decorate.
        decorators: Sequence of Click option/argument/command decorators.

    Returns:
        The fully-decorated function, cast back to its original signature type.
    """
    wrapped: Callable[..., Any] = function
    for decorator in decorators:
        wrapped = decorator(wrapped)
    return cast(_F, wrapped)


def _ignored_flag_option(name: str, help_text: str) -> Callable[[_F], _F]:
    return click.option(name, is_flag=True, default=False, expose_value=False, help=help_text)


def _ignored_string_option(
    name: str,
    help_text: str,
    default: str | None = None,
) -> Callable[[_F], _F]:
    return click.option(name, default=default, expose_value=False, help=help_text)


def _ignored_path_option(name: str, help_text: str) -> Callable[[_F], _F]:
    return click.option(
        name,
        type=click.Path(path_type=Path),
        default=None,
        expose_value=False,
        help=help_text,
    )


def _path_option(name: str, parameter_name: str, help_text: str) -> Callable[[_F], _F]:
    return click.option(
        name,
        parameter_name,
        type=click.Path(path_type=Path),
        default=None,
        help=help_text,
    )


def _ignored_int_option(name: str, help_text: str) -> Callable[[_F], _F]:
    return click.option(name, type=int, default=None, expose_value=False, help=help_text)


def _silent_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value:
        _state(ctx).is_silent = True


def _quiet_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value:
        _state(ctx).is_quiet = True


def _ansi_callback(ctx: click.Context, _param: click.Parameter, value: bool | None) -> None:
    if value is not None:
        ctx.color = value
        _state(ctx).should_use_ansi = value


def _no_interaction_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value:
        _state(ctx).is_interaction_disabled = True


def _verbose_callback(ctx: click.Context, _param: click.Parameter, value: int) -> None:
    if value:
        _state(ctx).verbosity = value


def _command_version_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        click.echo(f"{TOOL_NAME} {VERSION}")
        ctx.exit()


def _option(*param_decls: str, **attrs: Any) -> ClickDecorator:
    return cast(ClickDecorator, click.option(*param_decls, **attrs))


def _argument(*param_decls: str, **attrs: Any) -> ClickDecorator:
    return cast(ClickDecorator, click.argument(*param_decls, **attrs))


def _command(*args: Any, **attrs: Any) -> ClickDecorator:
    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        """Register *function* as a subcommand of the bound root group.

        Args:
            function: The command implementation to register.

        Returns:
            The Click-wrapped command callable.

        Raises:
            RuntimeError: If ``bind_cli_root`` has not been called first.
        """
        if _command_root is None:
            raise RuntimeError("CLI root group has not been bound.")
        command_attrs = dict(attrs)
        command_attrs.setdefault("help", _doc_summary(function))
        return cast(Callable[..., Any], _command_root.command(*args, **command_attrs)(function))

    return decorator


def _doc_summary(function: Callable[..., Any]) -> str:
    """Return the first docstring paragraph for Click command help."""
    doc = inspect.getdoc(function) or ""
    return doc.split("\n\n", 1)[0]


def _pass_context(function: _F) -> _F:
    return cast(_F, click.pass_context(function))


def analyse_command(function: _F) -> _F:
    """Wire *function* up as the ``analyse`` subcommand with its full option set.

    Adds the global flags (``--silent``, ``--quiet``, ``--ansi``, etc.) plus
    analyse-specific options for rule/pillar filtering, fail-on, output
    format, config, and the PHP-port compatibility flags.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff analyse``.
    """
    return apply_decorators(function, _ANALYSE_COMMAND_DECORATORS)


def dashboard_command(function: _F) -> _F:
    """Wire *function* up as the ``dashboard`` subcommand serving the live HTTP UI.

    Adds ``--host``/``--port``/``--scan-timeout`` and baseline/diff aliases
    on top of the global flags.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff dashboard``.
    """
    return apply_decorators(function, _DASHBOARD_COMMAND_DECORATORS)


def list_rules_command(function: _F) -> _F:
    """Wire *function* up as the ``list-rules`` subcommand (table or JSON output).

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff list-rules``.
    """
    return apply_decorators(function, _LIST_RULES_COMMAND_DECORATORS)


def report_command(function: _F) -> _F:
    """Wire *function* up as the ``report`` subcommand for writing HTML/JSON to disk.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff report``.
    """
    return apply_decorators(function, _REPORT_COMMAND_DECORATORS)


def summary_command(function: _F) -> _F:
    """Wire *function* up as the ``summary`` subcommand for top-N rule/file digests.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff summary``.
    """
    return apply_decorators(function, _SUMMARY_COMMAND_DECORATORS)


def metric_calibration_command(function: _F) -> _F:
    """Wire *function* up as the hidden ``metric-calibration`` subcommand.

    Hidden from ``--help`` listings; used during rule tuning to inspect the
    distribution of metric values across the codebase.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff metric-calibration``.
    """
    return apply_decorators(function, _METRIC_CALIBRATION_COMMAND_DECORATORS)


def list_command(function: _F) -> _F:
    """Wire *function* up as the ``list`` subcommand (introspect available commands).

    Supports ``--format`` for txt/xml/json/md output and ``--raw`` for a bare
    command listing.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff list``.
    """
    return apply_decorators(function, _LIST_COMMAND_DECORATORS)


def help_command_decorator(function: _F) -> _F:
    """Wire *function* up as the ``help`` subcommand (per-command help text).

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff help``.
    """
    return apply_decorators(function, _HELP_COMMAND_DECORATORS)


def init_command(function: _F) -> _F:
    """Wire *function* up as the ``init`` subcommand for writing a default ``.gruff-py.yaml``.

    Adds ``--force`` to regenerate an existing file on top of the global flags.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff init``.
    """
    return apply_decorators(function, _INIT_COMMAND_DECORATORS)


def completion_command(function: _F) -> _F:
    """Wire *function* up as the ``completion`` subcommand for shell completion scripts.

    ``--debug`` tails the completion debug log for troubleshooting wonky
    shell integrations.

    Args:
        function: The command implementation.

    Returns:
        The decorated function registered as ``gruff completion``.
    """
    return apply_decorators(function, _COMPLETION_COMMAND_DECORATORS)


_GLOBAL_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _option(
        "--silent",
        is_flag=True,
        expose_value=False,
        callback=_silent_callback,
        help="Do not output any message.",
    ),
    _option(
        "-q",
        "--quiet",
        is_flag=True,
        expose_value=False,
        callback=_quiet_callback,
        help="Only errors are displayed. All other output is suppressed.",
    ),
    _option(
        "-V",
        "--version",
        is_flag=True,
        expose_value=False,
        is_eager=True,
        callback=_command_version_callback,
        help="Display this application version.",
    ),
    _option(
        "--ansi/--no-ansi",
        default=None,
        expose_value=False,
        callback=_ansi_callback,
        help="Force or disable ANSI output.",
    ),
    _option(
        "-n",
        "--no-interaction",
        is_flag=True,
        expose_value=False,
        callback=_no_interaction_callback,
        help="Do not ask any interactive question.",
    ),
    _option(
        "-v",
        "--verbose",
        count=True,
        expose_value=False,
        callback=_verbose_callback,
        help="Increase message verbosity. Use -v, -vv, or -vvv.",
    ),
)

_ANALYSIS_COMPAT_DECORATORS: tuple[ClickDecorator, ...] = (
    _ignored_path_option("--infection-report", "Path to a full Infection JSON report to ingest."),
    _ignored_flag_option("--infection-run", "Run Infection before ingesting --infection-report."),
    _ignored_string_option(
        "--infection-bin", "Infection executable for --infection-run.", "infection"
    ),
    _ignored_path_option("--infection-config", "Path to infection.json5 for --infection-run."),
    _ignored_string_option(
        "--infection-test-framework-options",
        "Options passed to Infection/PHPUnit for --infection-run.",
    ),
    _ignored_path_option(
        "--mutation-baseline",
        "Path to a baseline Infection JSON report for MSI diff mode.",
    ),
    _ignored_int_option("--mutation-budget", "Maximum escaped/timed-out mutants allowed."),
    _ignored_string_option(
        "--diff",
        "Filter findings to changed lines. Use working-tree, staged, unstaged, or a base ref.",
    ),
    _ignored_string_option("--diff-vs", "Compare current findings against a base Git ref."),
    _ignored_flag_option("--changed-only", "With --diff-vs, compare only changed files."),
    _ignored_path_option(
        "--paths-relative-to",
        "Normalize absolute finding paths relative to this directory for reports.",
    ),
    _ignored_path_option("--history-file", "Append score trend history to this JSON file."),
    _path_option(
        "--baseline-path",
        "baseline_path",
        f'Apply this baseline JSON file instead of the default "{DEFAULT_BASELINE_FILENAME}".',
    ),
    _option(
        "--generate-baseline",
        "generate_baseline",
        is_flag=True,
        default=False,
        help=f'Write current findings to "{DEFAULT_BASELINE_FILENAME}".',
    ),
    _path_option(
        "--generate-baseline-path",
        "generate_baseline_path",
        "Write current findings to this baseline JSON file (implies generation).",
    ),
    _option(
        "--no-baseline",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default baseline file for this run.",
    ),
)

_REPORT_COMPAT_DECORATORS: tuple[ClickDecorator, ...] = (
    _ignored_path_option("--infection-report", "Path to a full Infection JSON report to ingest."),
    _ignored_path_option(
        "--mutation-baseline",
        "Path to a baseline Infection JSON report for MSI diff mode.",
    ),
    _ignored_int_option("--mutation-budget", "Maximum escaped/timed-out mutants allowed."),
    _ignored_string_option(
        "--diff",
        "Filter findings to changed lines. Use working-tree, staged, unstaged, or a base ref.",
    ),
    _ignored_string_option("--diff-vs", "Compare current findings against a base Git ref."),
    _ignored_flag_option("--changed-only", "With --diff-vs, compare only changed files."),
    _ignored_path_option(
        "--paths-relative-to",
        "Normalize absolute finding paths relative to this directory for reports.",
    ),
    _ignored_path_option("--history-file", "Append score trend history to this JSON file."),
    _path_option(
        "--baseline-path",
        "baseline_path",
        f'Apply this baseline JSON file instead of the default "{DEFAULT_BASELINE_FILENAME}".',
    ),
    _option(
        "--no-baseline",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default baseline file for this run.",
    ),
)

_ANALYSE_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    *_ANALYSIS_COMPAT_DECORATORS,
    _option(
        "--exclude-rule",
        multiple=True,
        help="Hide these comma-separated rule IDs or repeated values.",
    ),
    _option(
        "--include-rule",
        multiple=True,
        help="Display only these comma-separated rule IDs or repeated values.",
    ),
    _option(
        "--exclude-pillar",
        multiple=True,
        help="Hide these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        help="Display only these comma-separated pillars or repeated values.",
    ),
    _option(
        "--min-severity",
        type=click.Choice([s.value for s in Severity]),
        default=None,
        help="Display only findings at or above advisory, warning, or error.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters.",
    ),
    _option(
        "--report-editor-link",
        type=click.Choice(["vscode", "phpstorm", "none"]),
        default="none",
        show_default=True,
        help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="error",
        show_default=True,
        help="Finding severity that fails the run: advisory, warning, error, or none.",
    ),
    _option(
        "--format",
        "output_format",
        type=click.Choice([f.value for f in OutputFormat]),
        default="text",
        show_default=True,
        help="Output format: text, json, html, markdown, github, hotspot, or sarif.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_DASHBOARD_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters in dashboard scans.",
    ),
    _option(
        "--project-root",
        "project_root",
        type=click.Path(path_type=Path),
        default=None,
        help="Alias for --project.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--diff",
        is_flag=True,
        default=False,
        expose_value=False,
        help="Start the dashboard in diff-only scan mode.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for dashboard scans.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Initial gruff YAML or TOML config path (.yaml, .yml, or .toml).",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="none",
        show_default=True,
        help="Finding severity that fails the scan: advisory, warning, error, or none.",
    ),
    _option(
        "--scan-timeout",
        type=int,
        default=120,
        show_default=True,
        expose_value=False,
        help="Seconds to allow each refresh scan. Use 0 to disable.",
    ),
    _option(
        "--port",
        type=int,
        default=8765,
        show_default=True,
        help="Port for the dashboard server.",
    ),
    _option(
        "--host",
        default="127.0.0.1",
        show_default=True,
        help="Host for the dashboard server.",
    ),
    _option(
        "--project",
        "project_root",
        type=click.Path(path_type=Path),
        default=None,
        help="Initial project root for scans.",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_LIST_RULES_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--format",
        "rule_format",
        type=click.Choice(["text", "table", "json"]),
        default="table",
        show_default=True,
        help="Output format: text, table, or json.",
    ),
    _command("list-rules"),
)

_REPORT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    *_REPORT_COMPAT_DECORATORS,
    _option(
        "--exclude-rule",
        multiple=True,
        help="Hide these comma-separated rule IDs or repeated values.",
    ),
    _option(
        "--include-rule",
        multiple=True,
        help="Display only these comma-separated rule IDs or repeated values.",
    ),
    _option(
        "--exclude-pillar",
        multiple=True,
        help="Hide these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        help="Display only these comma-separated pillars or repeated values.",
    ),
    _option(
        "--min-severity",
        type=click.Choice([s.value for s in Severity]),
        default=None,
        help="Display only findings at or above advisory, warning, or error.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters.",
    ),
    _option(
        "--report-editor-link",
        type=click.Choice(["vscode", "phpstorm", "none"]),
        default="none",
        show_default=True,
        help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="none",
        show_default=True,
        help="Finding severity that fails the scan: advisory, warning, error, or none.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _option(
        "--output",
        "output_path",
        type=click.Path(path_type=Path),
        help="Write the report to this file.",
    ),
    _option(
        "--format",
        "report_format",
        type=click.Choice(["html", "json"]),
        default="html",
        show_default=True,
        help="Report format: html or json.",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_SUMMARY_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--top",
        type=int,
        default=10,
        show_default=True,
        help="How many top rules and file offenders to list.",
    ),
    _option(
        "--format",
        "summary_format",
        type=click.Choice(["text", "json"]),
        default="text",
        show_default=True,
        help="Output format: text or json.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_METRIC_CALIBRATION_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--top",
        type=int,
        default=10,
        show_default=True,
        help="How many top functions to list for each metric.",
    ),
    _option(
        "--format",
        "calibration_format",
        type=click.Choice(["text", "json"]),
        default="text",
        show_default=True,
        help="Output format: text or json.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command("metric-calibration", hidden=True),
)

_LIST_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _option("--short", is_flag=True, help="Skip describing command arguments."),
    _option(
        "--format",
        "list_format",
        type=click.Choice(["txt", "xml", "json", "md"]),
        default="txt",
        show_default=True,
        help="The output format.",
    ),
    _option("--raw", is_flag=True, help="Output raw command list."),
    _argument("namespace", required=False),
    _command("list"),
)

_HELP_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _argument("command_name", required=False),
    _command("help"),
)

_COMPLETION_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _option("--debug", is_flag=True, help="Tail the completion debug log."),
    _argument("shell", required=False),
    _command(),
)

_INIT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--force",
        is_flag=True,
        default=False,
        help="Regenerate an existing .gruff-py.yaml file, preserving paths.ignore.",
    ),
    _command(),
)
