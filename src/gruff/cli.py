"""Click-based CLI entry point for `gruff`."""

import json
import os
import shlex
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar, cast

import click
from click.shell_completion import get_completion_class

from gruff.analysis.report import AnalysisReport
from gruff.analysis.runner import run_analysis
from gruff.command.dashboard_server import DashboardState, create_dashboard_server
from gruff.finding.fail_threshold import FailThreshold
from gruff.finding.output_format import OutputFormat
from gruff.finding.pillar import Pillar
from gruff.finding.severity import Severity
from gruff.reporting.finding_display_filter import FindingDisplayFilter
from gruff.reporting.github_annotations_reporter import GithubAnnotationsReporter
from gruff.reporting.hotspot_reporter import HotspotReporter
from gruff.reporting.html_reporter import HtmlReporter
from gruff.reporting.json_reporter import JsonReporter
from gruff.reporting.markdown_reporter import MarkdownReporter
from gruff.reporting.sarif_reporter import SarifReporter
from gruff.reporting.text_reporter import TextReporter
from gruff.rule.definition import RuleDefinition
from gruff.rule.registry import RuleRegistry
from gruff.version import VERSION

_F = TypeVar("_F", bound=Callable[..., Any])


class GruffGroup(click.Group):
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write(_root_menu(ctx))


@dataclass(slots=True)
class CliState:
    silent: bool = False
    quiet: bool = False
    ansi: bool | None = None
    no_interaction: bool = False
    verbosity: int = 0

    @property
    def suppress_output(self) -> bool:
        return self.silent or self.quiet


@click.group(
    cls=GruffGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.option("--silent", is_flag=True, help="Do not output any message.")
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Only errors are displayed. All other output is suppressed.",
)
@click.version_option(VERSION, "-V", "--version", prog_name="gruff", message="gruff %(version)s")
@click.option("--ansi/--no-ansi", default=None, help="Force or disable ANSI output.")
@click.option(
    "-n",
    "--no-interaction",
    is_flag=True,
    help="Do not ask any interactive question.",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase message verbosity. Use -v, -vv, or -vvv.",
)
@click.pass_context
def main(
    ctx: click.Context,
    silent: bool,
    quiet: bool,
    ansi: bool | None,
    no_interaction: bool,
    verbose: int,
) -> None:
    """gruff - Python project quality analyser."""
    if ansi is not None:
        ctx.color = ansi
    ctx.obj = CliState(
        silent=silent,
        quiet=quiet,
        ansi=ansi,
        no_interaction=no_interaction,
        verbosity=verbose,
    )
    if ctx.invoked_subcommand is None:
        if not _state(ctx).suppress_output:
            click.echo(_root_menu(ctx), color=_echo_color(ctx), nl=False)
        ctx.exit(0)


def _state(ctx: click.Context | None = None) -> CliState:
    current = ctx or click.get_current_context(silent=True)
    while current is not None:
        if isinstance(current.obj, CliState):
            return current.obj
        current = current.parent
    return CliState()


def _global_command_options(function: _F) -> _F:
    decorators: Iterable[Callable[[_F], _F]] = (
        cast(
            Callable[[_F], _F],
            click.option(
                "--silent",
                is_flag=True,
                expose_value=False,
                callback=_silent_callback,
                help="Do not output any message.",
            ),
        ),
        cast(
            Callable[[_F], _F],
            click.option(
                "-q",
                "--quiet",
                is_flag=True,
                expose_value=False,
                callback=_quiet_callback,
                help="Only errors are displayed. All other output is suppressed.",
            ),
        ),
        cast(
            Callable[[_F], _F],
            click.option(
                "-V",
                "--version",
                is_flag=True,
                expose_value=False,
                is_eager=True,
                callback=_command_version_callback,
                help="Display this application version.",
            ),
        ),
        cast(
            Callable[[_F], _F],
            click.option(
                "--ansi/--no-ansi",
                default=None,
                expose_value=False,
                callback=_ansi_callback,
                help="Force or disable ANSI output.",
            ),
        ),
        cast(
            Callable[[_F], _F],
            click.option(
                "-n",
                "--no-interaction",
                is_flag=True,
                expose_value=False,
                callback=_no_interaction_callback,
                help="Do not ask any interactive question.",
            ),
        ),
        cast(
            Callable[[_F], _F],
            click.option(
                "-v",
                "--verbose",
                count=True,
                expose_value=False,
                callback=_verbose_callback,
                help="Increase message verbosity. Use -v, -vv, or -vvv.",
            ),
        ),
    )
    for decorator in decorators:
        function = decorator(function)
    return function


def _analysis_compat_options(function: _F) -> _F:
    decorators: Iterable[Callable[[_F], _F]] = (
        _ignored_path_option(
            "--infection-report", "Path to a full Infection JSON report to ingest."
        ),
        _ignored_flag_option(
            "--infection-run", "Run Infection before ingesting --infection-report."
        ),
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
        _ignored_string_option(
            "--diff-vs",
            "Compare current findings against a base Git ref.",
        ),
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
            "Write current findings to a gruff baseline JSON file. "
            'Defaults to "gruff-baseline.json".',
        ),
        _ignored_flag_option("--no-baseline", "Skip auto-applying the default baseline file."),
    )
    for decorator in decorators:
        function = decorator(function)
    return function


def _report_compat_options(function: _F) -> _F:
    decorators: Iterable[Callable[[_F], _F]] = (
        _ignored_path_option(
            "--infection-report", "Path to a full Infection JSON report to ingest."
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
        _ignored_string_option(
            "--diff-vs",
            "Compare current findings against a base Git ref.",
        ),
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
    for decorator in decorators:
        function = decorator(function)
    return function


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
        _state(ctx).silent = True


def _quiet_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value:
        _state(ctx).quiet = True


def _ansi_callback(ctx: click.Context, _param: click.Parameter, value: bool | None) -> None:
    if value is not None:
        ctx.color = value
        _state(ctx).ansi = value


def _no_interaction_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value:
        _state(ctx).no_interaction = True


def _verbose_callback(ctx: click.Context, _param: click.Parameter, value: int) -> None:
    if value:
        _state(ctx).verbosity = value


def _command_version_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        click.echo(f"gruff {VERSION}")
        ctx.exit()


def _root_menu(ctx: click.Context) -> str:
    return "\n".join(
        [
            f"gruff {_style(VERSION, 'green', ctx)}",
            "",
            _section("Usage:", ctx),
            "  command [options] [arguments]",
            "",
            _section("Options:", ctx),
            _option_line(
                "-h, --help",
                "Display help for the given command. When no command is given display help for the "
                f"{_style('list', 'green', ctx)} command",
                ctx,
            ),
            _option_line("    --silent", "Do not output any message", ctx),
            _option_line(
                "-q, --quiet",
                "Only errors are displayed. All other output is suppressed",
                ctx,
            ),
            _option_line("-V, --version", "Display this application version", ctx),
            _option_line(
                "    --ansi|--no-ansi",
                "Force (or disable --no-ansi) ANSI output",
                ctx,
            ),
            _option_line(
                "-n, --no-interaction",
                "Do not ask any interactive question",
                ctx,
            ),
            _option_line(
                "-v|vv|vvv, --verbose",
                "Increase the verbosity of messages: 1 for normal output, 2 for more "
                "verbose output and 3 for debug",
                ctx,
            ),
            "",
            _section("Available commands:", ctx),
            _command_line("analyse", "Run gruff analysis.", ctx),
            _command_line("completion", "Dump the shell completion script", ctx),
            _command_line("dashboard", "Serve the local gruff dashboard.", ctx),
            _command_line("help", "Display help for a command", ctx),
            _command_line("list", "List commands", ctx),
            _command_line("list-rules", "List gruff rule metadata.", ctx),
            _command_line("report", "Render a gruff report to stdout or a file.", ctx),
            _command_line(
                "summary",
                "Print a compact digest of a scan: per-pillar finding counts, top rules, and top "
                "file offenders. Runs the analyser once and renders only the summary; no "
                "per-finding spam.",
                ctx,
            ),
            "",
        ]
    )


def _section(label: str, ctx: click.Context) -> str:
    return _style(label, "yellow", ctx)


def _option_line(label: str, description: str, ctx: click.Context) -> str:
    return f"  {_style(label, 'green', ctx)}{' ' * (22 - len(label))}{description}"


def _command_line(name: str, description: str, ctx: click.Context) -> str:
    return f"  {_style(name, 'green', ctx)}{' ' * (12 - len(name))}{description}"


def _style(text: str, color: str, ctx: click.Context) -> str:
    if _color_setting(ctx) is False:
        return text
    return click.style(text, fg=color)


def _echo_color(ctx: click.Context) -> bool | None:
    return _color_setting(ctx)


def _color_setting(ctx: click.Context) -> bool | None:
    params = getattr(ctx, "params", {})
    if "ansi" in params:
        value = params["ansi"]
        if isinstance(value, bool):
            return value
    state = _state(ctx)
    if state.ansi is not None:
        return state.ansi
    return ctx.color


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a gruff YAML config file (.yaml or .yml).",
)
@click.option(
    "--no-config",
    is_flag=True,
    default=False,
    help="Skip auto-applying the default .gruff.yaml file for this run.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice([f.value for f in OutputFormat]),
    default="text",
    show_default=True,
    help="Output format: text, json, html, markdown, github, hotspot, or sarif.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailThreshold]),
    default="error",
    show_default=True,
    help="Finding severity that fails the run: advisory, warning, error, or none.",
)
@click.option(
    "--report-editor-link",
    type=click.Choice(["vscode", "phpstorm", "none"]),
    default="none",
    show_default=True,
    help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
)
@click.option(
    "--report-interactive",
    is_flag=True,
    default=False,
    help="Render opt-in interactive HTML finding filters.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Include files under default ignored directories.",
)
@click.option(
    "--min-severity",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Display only findings at or above advisory, warning, or error.",
)
@click.option(
    "--include-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Display only these comma-separated pillars or repeated values.",
)
@click.option(
    "--exclude-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Hide these comma-separated pillars or repeated values.",
)
@click.option(
    "--include-rule",
    multiple=True,
    help="Display only these comma-separated rule IDs or repeated values.",
)
@click.option(
    "--exclude-rule",
    multiple=True,
    help="Hide these comma-separated rule IDs or repeated values.",
)
@_analysis_compat_options
@_global_command_options
def analyse(
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    output_format: str,
    fail_on: str,
    report_editor_link: str,
    report_interactive: bool,
    include_ignored: bool,
    min_severity: str | None,
    include_pillar: tuple[str, ...],
    exclude_pillar: tuple[str, ...],
    include_rule: tuple[str, ...],
    exclude_rule: tuple[str, ...],
) -> None:
    """Run gruff analysis."""
    output = OutputFormat(output_format)
    report = _run_analysis_for_cli(
        paths=paths,
        config_path=config_path,
        no_config=no_config,
        output=output,
        fail_on=FailThreshold(fail_on),
        include_ignored=include_ignored,
        min_severity=min_severity,
        include_pillar=include_pillar,
        exclude_pillar=exclude_pillar,
        include_rule=include_rule,
        exclude_rule=exclude_rule,
    )
    _write_stdout(
        _render_report(
            report,
            output,
            project_root=str(Path.cwd()),
            report_editor_link=report_editor_link,
            report_interactive=report_interactive,
        )
    )
    sys.exit(report.exit_code)


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--project",
    "project_root",
    type=click.Path(path_type=Path),
    default=None,
    help="Initial project root for scans.",
)
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host for the dashboard server.",
)
@click.option(
    "--port",
    type=int,
    default=8765,
    show_default=True,
    help="Port for the dashboard server.",
)
@click.option(
    "--scan-timeout",
    type=int,
    default=120,
    show_default=True,
    expose_value=False,
    help="Seconds to allow each refresh scan. Use 0 to disable.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailThreshold]),
    default="none",
    show_default=True,
    help="Finding severity that fails the scan: advisory, warning, error, or none.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Initial gruff YAML config path (.yaml or .yml).",
)
@click.option(
    "--no-config",
    is_flag=True,
    default=False,
    help="Skip auto-applying the default .gruff.yaml file for dashboard scans.",
)
@click.option(
    "--diff",
    is_flag=True,
    default=False,
    expose_value=False,
    help="Start the dashboard in diff-only scan mode.",
)
@click.option(
    "--baseline",
    type=click.Path(path_type=Path),
    default=None,
    expose_value=False,
    help='Initial gruff baseline JSON path. Defaults to "gruff-baseline.json".',
)
@click.option(
    "--no-baseline",
    is_flag=True,
    default=False,
    expose_value=False,
    help="Skip auto-applying the default baseline file for dashboard scans.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Include files under default ignored directories.",
)
@click.option(
    "--project-root",
    "project_root",
    type=click.Path(path_type=Path),
    default=None,
    help="Alias for --project.",
)
@click.option(
    "--report-interactive",
    is_flag=True,
    default=False,
    help="Render opt-in interactive HTML finding filters in dashboard scans.",
)
@_global_command_options
def dashboard(
    paths: tuple[str, ...],
    project_root: Path | None,
    host: str,
    port: int,
    fail_on: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    report_interactive: bool,
) -> None:
    """Serve the local gruff dashboard."""
    launch_root = Path.cwd()
    project = (project_root or launch_root).resolve()
    if not project.is_dir():
        raise click.ClickException(f"Project root is not a directory: {project}")
    if port < 0 or port > 65535:
        raise click.ClickException("--port must be between 0 and 65535.")

    initial_state = DashboardState(
        project=str(project),
        paths=" ".join(shlex.quote(path) for path in (paths or (".",))),
        fail_on=fail_on,
        config=str(config_path) if config_path is not None else "",
        no_config=no_config,
        include_ignored=include_ignored,
        report_interactive=report_interactive,
    )
    server = create_dashboard_server(
        host=host,
        port=port,
        launch_root=launch_root,
        initial_state=initial_state,
    )
    bound_host, actual_port = server.server_address[:2]
    actual_host = bound_host.decode("utf-8") if isinstance(bound_host, bytes) else bound_host
    _write_stdout(f"gruff dashboard serving at http://{actual_host}:{actual_port}/\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _write_stdout("gruff dashboard stopped\n")
    finally:
        server.server_close()


@main.command("list-rules")
@click.option(
    "--format",
    "rule_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format: table or json.",
)
@_global_command_options
def list_rules(rule_format: str) -> None:
    """List gruff rule metadata."""
    definitions = [rule.definition() for rule in RuleRegistry.defaults().all()]
    if rule_format == "json":
        _write_stdout(json.dumps({"rules": [_rule_payload(d) for d in definitions]}, indent=4))
        _write_stdout("\n")
        return
    _write_stdout(_format_rule_table(definitions))


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["html", "json"]),
    default="html",
    show_default=True,
    help="Report format: html or json.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write the report to this file.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a gruff YAML config file (.yaml or .yml).",
)
@click.option(
    "--no-config",
    is_flag=True,
    default=False,
    help="Skip auto-applying the default .gruff.yaml file for this run.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailThreshold]),
    default="none",
    show_default=True,
    help="Finding severity that fails the scan: advisory, warning, error, or none.",
)
@click.option(
    "--report-editor-link",
    type=click.Choice(["vscode", "phpstorm", "none"]),
    default="none",
    show_default=True,
    help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
)
@click.option(
    "--report-interactive",
    is_flag=True,
    default=False,
    help="Render opt-in interactive HTML finding filters.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Include files under default ignored directories.",
)
@click.option(
    "--min-severity",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Display only findings at or above advisory, warning, or error.",
)
@click.option(
    "--include-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Display only these comma-separated pillars or repeated values.",
)
@click.option(
    "--exclude-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Hide these comma-separated pillars or repeated values.",
)
@click.option(
    "--include-rule",
    multiple=True,
    help="Display only these comma-separated rule IDs or repeated values.",
)
@click.option(
    "--exclude-rule",
    multiple=True,
    help="Hide these comma-separated rule IDs or repeated values.",
)
@_report_compat_options
@_global_command_options
def report(
    paths: tuple[str, ...],
    report_format: str,
    output_path: Path | None,
    config_path: Path | None,
    no_config: bool,
    fail_on: str,
    report_editor_link: str,
    report_interactive: bool,
    include_ignored: bool,
    min_severity: str | None,
    include_pillar: tuple[str, ...],
    exclude_pillar: tuple[str, ...],
    include_rule: tuple[str, ...],
    exclude_rule: tuple[str, ...],
) -> None:
    """Render a gruff report to stdout or a file."""
    output = OutputFormat(report_format)
    analysis_report = _run_analysis_for_cli(
        paths=paths,
        config_path=config_path,
        no_config=no_config,
        output=output,
        fail_on=FailThreshold(fail_on),
        include_ignored=include_ignored,
        min_severity=min_severity,
        include_pillar=include_pillar,
        exclude_pillar=exclude_pillar,
        include_rule=include_rule,
        exclude_rule=exclude_rule,
    )
    rendered = _render_report(
        analysis_report,
        output,
        project_root=str(Path.cwd()),
        report_editor_link=report_editor_link,
        report_interactive=report_interactive,
    )
    if output_path is not None:
        output_path.write_text(rendered)
    else:
        _write_stdout(rendered)
    sys.exit(analysis_report.exit_code)


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a gruff YAML config file (.yaml or .yml).",
)
@click.option(
    "--no-config",
    is_flag=True,
    default=False,
    help="Skip auto-applying the default .gruff.yaml file for this run.",
)
@click.option(
    "--format",
    "summary_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format: text or json.",
)
@click.option(
    "--top",
    type=int,
    default=10,
    show_default=True,
    help="How many top rules and file offenders to list.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Include files under default ignored directories.",
)
@_global_command_options
def summary(
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    summary_format: str,
    top: int,
    include_ignored: bool,
) -> None:
    """Print a compact digest of a scan."""
    if top < 1:
        raise click.ClickException("--top must be greater than 0.")
    analysis_report = _run_analysis_for_cli(
        paths=paths,
        config_path=config_path,
        no_config=no_config,
        output=OutputFormat.JSON if summary_format == "json" else OutputFormat.TEXT,
        fail_on=FailThreshold.NONE,
        include_ignored=include_ignored,
        min_severity=None,
        include_pillar=(),
        exclude_pillar=(),
        include_rule=(),
        exclude_rule=(),
    )
    if summary_format == "json":
        _write_stdout(json.dumps(_summary_payload(analysis_report, top), indent=4))
        _write_stdout("\n")
    else:
        _write_stdout(_summary_text(analysis_report, top))
    sys.exit(analysis_report.exit_code)


@main.command("list")
@click.argument("namespace", required=False)
@click.option("--raw", is_flag=True, help="Output raw command list.")
@click.option(
    "--format",
    "list_format",
    type=click.Choice(["txt", "xml", "json", "md"]),
    default="txt",
    show_default=True,
    help="The output format.",
)
@click.option("--short", is_flag=True, help="Skip describing command arguments.")
@_global_command_options
@click.pass_context
def list_commands(
    ctx: click.Context,
    namespace: str | None,
    raw: bool,
    list_format: str,
    short: bool,
) -> None:
    """List commands."""
    rows = _command_rows(_root_group(ctx), namespace)
    if raw:
        _write_stdout("".join(f"{name}\n" for name, _help in rows))
        return
    if list_format == "json":
        _write_stdout(
            json.dumps(
                {
                    "commands": [
                        {"name": name, "description": help_text} for name, help_text in rows
                    ]
                },
                indent=4,
            )
            + "\n"
        )
        return
    if list_format == "xml":
        commands = "".join(
            f'<command name="{_xml_escape(name)}">{_xml_escape(help_text)}</command>'
            for name, help_text in rows
        )
        _write_stdout(f"<commands>{commands}</commands>\n")
        return
    if list_format == "md":
        lines = ["# gruff commands", ""]
        for name, help_text in rows:
            lines.append(f"- `{name}`" if short or not help_text else f"- `{name}` - {help_text}")
        _write_stdout("\n".join(lines) + "\n")
        return
    width = max((len(name) for name, _help in rows), default=0)
    lines = ["Available commands:"]
    for name, help_text in rows:
        lines.append(f"  {name:<{width}}  {'' if short else help_text}".rstrip())
    _write_stdout("\n".join(lines) + "\n")


@main.command("help")
@click.argument("command_name", required=False)
@_global_command_options
@click.pass_context
def help_command(ctx: click.Context, command_name: str | None) -> None:
    """Display help for a command."""
    root = _root_group(ctx)
    if command_name is None:
        _write_stdout(ctx.find_root().get_help() + "\n")
        return
    command = root.get_command(ctx, command_name)
    if command is None:
        raise click.ClickException(f'Command "{command_name}" is not defined.')
    with click.Context(command, info_name=command_name, parent=ctx.find_root()) as command_ctx:
        _write_stdout(command.get_help(command_ctx) + "\n")


@main.command()
@click.argument("shell", required=False)
@click.option("--debug", is_flag=True, help="Tail the completion debug log.")
@_global_command_options
@click.pass_context
def completion(ctx: click.Context, shell: str | None, debug: bool) -> None:
    """Dump the shell completion script."""
    if debug:
        raise click.ClickException("Completion debug logs are not implemented in gruff-py.")
    resolved_shell = shell or _detect_shell()
    completion_class = get_completion_class(resolved_shell)
    if completion_class is None:
        raise click.ClickException(
            f'Unsupported shell "{resolved_shell}". Supported shells: bash, fish, zsh.'
        )
    source = completion_class(_root_group(ctx), {}, "gruff", "_GRUFF_COMPLETE").source()
    _write_stdout(source)
    if not source.endswith("\n"):
        _write_stdout("\n")


def _run_analysis_for_cli(
    *,
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    output: OutputFormat,
    fail_on: FailThreshold,
    include_ignored: bool,
    min_severity: str | None,
    include_pillar: tuple[str, ...],
    exclude_pillar: tuple[str, ...],
    include_rule: tuple[str, ...],
    exclude_rule: tuple[str, ...],
) -> AnalysisReport:
    display_filter = FindingDisplayFilter(
        min_severity=Severity(min_severity) if min_severity is not None else None,
        include_pillars=tuple(Pillar(value) for value in _split_repeated_csv(include_pillar)),
        exclude_pillars=tuple(Pillar(value) for value in _split_repeated_csv(exclude_pillar)),
        include_rules=_split_repeated_csv(include_rule),
        exclude_rules=_split_repeated_csv(exclude_rule),
    )
    return run_analysis(
        paths=paths,
        config_path=config_path,
        no_config=no_config,
        output=output,
        fail_threshold=fail_on,
        include_ignored=include_ignored,
        project_root=Path.cwd(),
        display_filter=display_filter,
    )


def _render_report(
    report: AnalysisReport,
    output: OutputFormat,
    *,
    project_root: str,
    report_editor_link: str,
    report_interactive: bool,
) -> str:
    match output:
        case OutputFormat.JSON:
            return JsonReporter().render(report)
        case OutputFormat.HTML:
            return HtmlReporter(project_root, report_editor_link, report_interactive).render(report)
        case OutputFormat.MARKDOWN:
            return MarkdownReporter().render(report)
        case OutputFormat.GITHUB:
            return GithubAnnotationsReporter().render(report)
        case OutputFormat.HOTSPOT:
            return HotspotReporter().render(report)
        case OutputFormat.SARIF:
            return SarifReporter().render(report)
        case OutputFormat.TEXT:
            return TextReporter().render(report)


def _summary_payload(report: AnalysisReport, top: int) -> dict[str, Any]:
    pillar_counts = Counter(finding.pillar.value for finding in report.findings)
    rule_counts = Counter(finding.rule_id for finding in report.findings)
    file_counts = Counter(finding.file_path for finding in report.findings)
    return {
        "summary": {
            "filesDiscovered": report.files_discovered,
            "filesParsed": report.files_parsed,
            "ignored": len(report.ignored_paths),
            "missing": len(report.missing_paths),
            "parseErrors": report.parse_error_count(),
            "findings": len(report.findings),
            "exitCode": report.exit_code,
        },
        "pillars": dict(sorted(pillar_counts.items())),
        "topRules": _counter_rows(rule_counts, top),
        "topFiles": _counter_rows(file_counts, top),
    }


def _summary_text(report: AnalysisReport, top: int) -> str:
    payload = _summary_payload(report, top)
    summary = payload["summary"]
    lines = [
        f"gruff {report.tool_version} summary",
        (
            f"Files: {summary['filesDiscovered']} discovered, {summary['filesParsed']} parsed, "
            f"{summary['ignored']} ignored, {summary['missing']} missing, "
            f"{summary['parseErrors']} parse errors"
        ),
        f"Findings: {summary['findings']}",
        "",
        "Per pillar:",
    ]
    pillars = cast(dict[str, int], payload["pillars"])
    if pillars:
        lines.extend(f"  {name}: {count}" for name, count in pillars.items())
    else:
        lines.append("  none")
    lines.extend(["", "Top rules:"])
    lines.extend(_format_count_rows(cast(list[dict[str, Any]], payload["topRules"])))
    lines.extend(["", "Top files:"])
    lines.extend(_format_count_rows(cast(list[dict[str, Any]], payload["topFiles"])))
    return "\n".join(lines) + "\n"


def _counter_rows(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in counter.most_common(top)]


def _format_count_rows(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["  none"]
    return [f"  {row['name']}: {row['count']}" for row in rows]


def _rule_payload(definition: RuleDefinition) -> dict[str, Any]:
    return {
        "id": definition.id,
        "name": definition.name,
        "pillar": definition.pillar.value,
        "tier": definition.tier.value,
        "defaultSeverity": definition.default_severity.value,
        "confidence": definition.confidence.value,
        "defaultEnabled": definition.default_enabled,
        "thresholds": dict(definition.default_thresholds),
        "options": dict(definition.default_options),
        "description": definition.get_description(),
    }


def _format_rule_table(definitions: list[RuleDefinition]) -> str:
    headers = ("Rule", "Pillar", "Severity", "Confidence", "Enabled")
    rows = [
        (
            d.id,
            d.pillar.value,
            d.default_severity.value,
            d.confidence.value,
            "yes" if d.default_enabled else "no",
        )
        for d in definitions
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend(
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows
    )
    return "\n".join(lines) + "\n"


def _split_repeated_csv(values: tuple[str, ...]) -> tuple[str, ...]:
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            stripped = item.strip()
            if stripped:
                items.append(stripped)
    return tuple(dict.fromkeys(items))


def _write_stdout(text: str) -> None:
    if not _state().suppress_output:
        sys.stdout.write(text)


def _root_group(ctx: click.Context) -> click.Group:
    command = ctx.find_root().command
    if not isinstance(command, click.Group):
        raise click.ClickException("Root command is not a command group.")
    return command


def _command_rows(group: click.Group, namespace: str | None) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for name in group.list_commands(click.get_current_context()):
        if namespace is not None and not name.startswith(namespace):
            continue
        command = group.commands[name]
        if command.hidden:
            continue
        rows.append((name, command.get_short_help_str(limit=100)))
    return rows


def _detect_shell() -> str:
    shell = os.environ.get("SHELL", "")
    name = Path(shell).name
    return name or "bash"


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    )


if __name__ == "__main__":
    main()
