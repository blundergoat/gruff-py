"""Reusable Click option and command decorators shared by the CLI command tree."""

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar, cast

import click

from gruffpy.cli_state import state as _state
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.severity import Severity
from gruffpy.version import TOOL_NAME, VERSION

_F = TypeVar("_F", bound=Callable[..., Any])
ClickDecorator = Callable[[Callable[..., Any]], Callable[..., Any]]
_command_root: click.Group | None = None


def bind_root_group(root: click.Group) -> None:
    global _command_root
    _command_root = root


def apply_decorators(function: _F, decorators: Iterable[ClickDecorator]) -> _F:
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
        if _command_root is None:
            raise RuntimeError("CLI root group has not been bound.")
        return cast(Callable[..., Any], _command_root.command(*args, **attrs)(function))

    return decorator


def _pass_context(function: _F) -> _F:
    return cast(_F, click.pass_context(function))


def analyse_command(function: _F) -> _F:
    return apply_decorators(function, _ANALYSE_COMMAND_DECORATORS)


def dashboard_command(function: _F) -> _F:
    return apply_decorators(function, _DASHBOARD_COMMAND_DECORATORS)


def list_rules_command(function: _F) -> _F:
    return apply_decorators(function, _LIST_RULES_COMMAND_DECORATORS)


def report_command(function: _F) -> _F:
    return apply_decorators(function, _REPORT_COMMAND_DECORATORS)


def summary_command(function: _F) -> _F:
    return apply_decorators(function, _SUMMARY_COMMAND_DECORATORS)


def metric_calibration_command(function: _F) -> _F:
    return apply_decorators(function, _METRIC_CALIBRATION_COMMAND_DECORATORS)


def list_command(function: _F) -> _F:
    return apply_decorators(function, _LIST_COMMAND_DECORATORS)


def help_command_decorator(function: _F) -> _F:
    return apply_decorators(function, _HELP_COMMAND_DECORATORS)


def completion_command(function: _F) -> _F:
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
    _ignored_path_option(
        "--baseline",
        "Suppress findings that match a gruff baseline JSON file. "
        'Defaults to "gruff-baseline.json".',
    ),
    _ignored_path_option(
        "--generate-baseline",
        'Write current findings to a gruff baseline JSON file. Defaults to "gruff-baseline.json".',
    ),
    _ignored_flag_option("--no-baseline", "Skip auto-applying the default baseline file."),
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
    _ignored_path_option(
        "--baseline",
        "Suppress findings that match a gruff baseline JSON file. "
        'Defaults to "gruff-baseline.json".',
    ),
    _ignored_flag_option("--no-baseline", "Skip auto-applying the default baseline file."),
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
        type=click.Choice([p.value for p in Pillar]),
        help="Hide these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        type=click.Choice([p.value for p in Pillar]),
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
        help="Scan files under default-ignored directories and .gitignore exclusions.",
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
        help="Scan files under default-ignored directories and .gitignore exclusions.",
    ),
    _option(
        "--no-baseline",
        is_flag=True,
        default=False,
        expose_value=False,
        help="Skip auto-applying the default baseline file for dashboard scans.",
    ),
    _option(
        "--baseline",
        type=click.Path(path_type=Path),
        default=None,
        expose_value=False,
        help='Initial gruff baseline JSON path. Defaults to "gruff-baseline.json".',
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
        type=click.Choice(["table", "json"]),
        default="table",
        show_default=True,
        help="Output format: table or json.",
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
        type=click.Choice([p.value for p in Pillar]),
        help="Hide these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        type=click.Choice([p.value for p in Pillar]),
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
        help="Scan files under default-ignored directories and .gitignore exclusions.",
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
        help="Scan files under default-ignored directories and .gitignore exclusions.",
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
        help="Scan files under default-ignored directories and .gitignore exclusions.",
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
