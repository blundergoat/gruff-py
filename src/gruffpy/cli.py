"""Serve every gruff-py terminal journey through one Click command tree.

The entry point turns user options into analysis, report, configuration, and
dashboard requests while keeping their visible diagnostics consistent.
"""

import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar, cast

import click
from click.shell_completion import get_completion_class

import gruffpy.cli_dashboard as dashboard_cli
from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.analysis.report import AnalysisReport, MachineReportContext
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.runner import run_analysis
from gruffpy.cli_hook import hook as _hook_command
from gruffpy.cli_list_rules import list_rules_detail
from gruffpy.cli_menu import root_menu as _root_menu, should_use_color as _should_use_color
from gruffpy.cli_migrate_config import migrate_config as _migrate_config_command
from gruffpy.cli_options import (
    ClickDecorator,
    _option,
    analyse_command as _analyse_command,
    apply_decorators,
    bind_root_group,
    check_ignore_command as _check_ignore_command,
    completion_command as _completion_command,
    dashboard_command as _dashboard_command,
    help_command_decorator as _help_command_decorator,
    init_command as _init_command,
    list_command as _list_command,
    list_rules_command as _list_rules_command,
    metric_calibration_command as _metric_calibration_command,
    report_command as _report_command,
    summary_command as _summary_command,
    was_fail_on_set_on_cli,
)
from gruffpy.cli_state import CliState, state as _state
from gruffpy.cli_summary import summary_text
from gruffpy.command.check_ignore_verdict import (
    check_ignore_exit_code,
    classify_paths,
    render_check_ignore_json,
    render_check_ignore_text,
)
from gruffpy.command.dashboard_server import create_dashboard_server
from gruffpy.command.init_config import (
    existing_config_source,
    initialise_project_config,
    render_default_config_yaml,
)
from gruffpy.command.metric_calibration import (
    build_metric_calibration_report,
    metric_calibration_payload,
    render_metric_calibration_text,
)
from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.severity import Severity
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.reporting.github_annotations_reporter import GithubAnnotationsReporter
from gruffpy.reporting.hotspot_reporter import HotspotReporter
from gruffpy.reporting.html_reporter import HtmlReporter
from gruffpy.reporting.json_reporter import JsonReporter
from gruffpy.reporting.markdown_reporter import MarkdownReporter
from gruffpy.reporting.sarif_reporter import SarifReporter
from gruffpy.reporting.text_reporter import TextReporter
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import TOOL_NAME, VERSION

_F = TypeVar("_F", bound=Callable[..., Any])


class CliGroup(click.Group):
    """Route terminal invocations to the Click command selected by the user.

    A bare invocation shows the command menu.
    Subcommands share the same handling for global flags and optional diff values.
    """

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,  # gruff: disable=naming.abbreviation -- Click API name.
        standalone_mode: bool = True,
        **extra: Any,
    ) -> Any:
        """Run Click after normalising optional-value ``--diff`` usage.

        Args:
            args: Command-line arguments to pass through Click.
            prog_name: Program name Click should show in help and errors.
            complete_var: Shell-completion environment variable name from Click's API.
            standalone_mode: Whether Click should handle exceptions and process exit.
            extra: Additional Click keyword arguments.

        Returns:
            Result returned by Click's root command invocation.
        """
        return super().main(
            args=_normalise_optional_diff_args(args),
            prog_name=prog_name,
            complete_var=complete_var,
            standalone_mode=standalone_mode,
            **extra,
        )

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Write the root help menu.

        Args:
            ctx: Invocation context used to build the root command menu.
            formatter: Click formatter receiving the rendered help.

        Returns:
            None; writes the root menu to formatter.
        """
        formatter.write(_root_menu(ctx))


def _normalise_optional_diff_args(args: Sequence[str] | None) -> list[str]:
    """Let ``--diff`` behave like an optional-value flag for analyse/report.

    Click resolves ``args=None`` to ``sys.argv[1:]`` inside ``Command.main`` after this
    hook would run, so console-script / ``python -m`` calls arrive as ``None`` and bare
    ``--diff`` is never rewritten (CliRunner hid this); resolve ``sys.argv`` here too.

    Args:
        args: Caller-supplied arguments, or None to use the process command line.

    Returns:
        A copied argument list with bare --diff expanded for analyse and report only.
    """
    if args is None:
        args = sys.argv[1:]
    command_index = next(
        (index for index, value in enumerate(args) if value in {"analyse", "report"}),
        None,
    )
    if command_index is None:
        return list(args)
    normalised = list(args[: command_index + 1])
    tail = list(args[command_index + 1 :])
    index = 0
    while index < len(tail):
        value = tail[index]
        if value == "--diff":
            next_value = tail[index + 1] if index + 1 < len(tail) else None
            if next_value is None or (next_value.startswith("-") and next_value != "-"):
                normalised.append("--diff=working-tree")
            else:
                normalised.append(value)
                normalised.append(next_value)
                index += 1
        else:
            normalised.append(value)
        index += 1
    return normalised


@dataclass(frozen=True, slots=True)
class _AnalysisCliRequest:
    """Carry validated command-line settings to the analysis runner.

    `analyse`, `report` and `summary` share this request.
    It keeps choices about what to scan separate from how the result is displayed.
    """

    paths: tuple[str, ...]
    config_path: Path | None
    should_skip_config: bool
    output: OutputFormat
    fail_on: FailThreshold
    was_fail_on_set_on_cli: bool
    command_name: str
    report_editor_link: str
    should_render_interactive: bool
    should_include_ignored: bool
    min_severity: str | None
    include_pillar: tuple[str, ...]
    exclude_pillar: tuple[str, ...]
    include_rule: tuple[str, ...]
    exclude_rule: tuple[str, ...]
    baseline_path: Path | None
    generate_baseline_path: Path | None
    migrate_baseline_path: Path | None
    force_baseline_overwrite: bool
    should_skip_baseline: bool
    diff_mode: str
    diff_patch: str
    since: str
    changed_ranges: str | None
    changed_scope: str
    strict_config: bool = False
    deep_scan_budget: str = ""
    show_rule: tuple[str, ...] = ()
    hide_rule: tuple[str, ...] = ()
    show_pillar: tuple[str, ...] = ()
    hide_pillar: tuple[str, ...] = ()
    min_confidence: str | None = None
    fail_on_new: bool = False


_ROOT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    cast(ClickDecorator, click.pass_context),
    _option("-v", "--verbose", count=True, help="Increase message verbosity. Use -v, -vv, or -vvv."),
    _option("-n", "--no-interaction", is_flag=True, help="Do not ask any interactive question."),
    _option("--ansi/--no-ansi", default=None, help="Force or disable ANSI output."),
    cast(
        ClickDecorator,
        click.version_option(
            VERSION,
            "-V",
            "--version",
            prog_name=TOOL_NAME,
            message=f"{TOOL_NAME} %(version)s",
        ),
    ),
    _option(
        "-q",
        "--quiet",
        is_flag=True,
        help="Only errors are displayed. All other output is suppressed.",
    ),
    _option("--silent", is_flag=True, help="Do not output any message."),
    cast(
        ClickDecorator,
        click.group(
            name=TOOL_NAME,
            cls=CliGroup,
            context_settings={"help_option_names": ["-h", "--help"]},
            invoke_without_command=True,
        ),
    ),
)


def _root_command(function: _F) -> _F:
    """Apply the shared root options and command-group decorators.

    Args:
        function: Entry callback that initializes the root invocation state.

    Returns:
        The decorated entry point carrying the root group and its global flags.
    """
    return apply_decorators(function, _ROOT_COMMAND_DECORATORS)


@_root_command
def main(ctx: click.Context, **kwargs: Any) -> None:
    """gruff-py - Python project quality analyser.

    Args:
        ctx: Active Click context.
        kwargs: Click-supplied root options.
    """
    ansi = cast(bool | None, kwargs["ansi"])
    if ansi is not None:
        ctx.color = ansi
    ctx.obj = CliState(
        is_silent=cast(bool, kwargs["silent"]),
        is_quiet=cast(bool, kwargs["quiet"]),
        should_use_ansi=ansi,
        is_interaction_disabled=cast(bool, kwargs["no_interaction"]),
        verbosity=cast(int, kwargs["verbose"]),
    )
    if ctx.invoked_subcommand is None:
        if not _state(ctx).should_suppress_output:
            click.echo(_root_menu(ctx), color=_should_use_color(ctx), nl=False)
        ctx.exit(0)


main = cast(click.Group, main)
bind_root_group(main)
main.add_command(_hook_command)
main.add_command(_migrate_config_command)


@_analyse_command
def analyse(**kwargs: Any) -> None:
    """Run gruff analysis.

    Use this to check source paths, review findings and enforce a failure threshold from the terminal or CI.

    Args:
        kwargs: Click-supplied arguments and options.
    """
    request = _analysis_request(kwargs, output_key="output_format", command_name="analyse")
    report = _run_analysis_for_cli(request)
    _write_stdout(
        _render_report(
            report,
            request.output,
            project_root=report.machine_context.project_root,
            report_editor_link=request.report_editor_link,
            report_interactive=request.should_render_interactive,
        )
    )
    sys.exit(report.exit_code)


@_dashboard_command
def dashboard(**kwargs: Any) -> None:
    """Validate launch choices and serve the browser dashboard until stopped.

    Use this command for repeated scans controlled from a local browser.

    Args:
        kwargs: Click-supplied arguments and options.

    Raises:
        click.ClickException: The project, port, or remote-bind choice is invalid.
    """
    request = _dashboard_request(kwargs)
    dashboard_project_root = (request.project_root or Path.cwd()).resolve()
    # A missing project cannot seed the user's opening dashboard scan.
    if not dashboard_project_root.is_dir():
        raise click.ClickException(f"Project root is not a directory: {dashboard_project_root}")
    if not 0 <= request.port <= 65535:
        raise click.ClickException("--port must be between 0 and 65535.")
    public_bind_warning = dashboard_cli.remote_dashboard_bind_warning(request.host, request.has_acknowledged_public_bind)
    _maybe_prompt_to_init_config(
        request.config_path,
        request.should_skip_config,
        project_root=dashboard_project_root,
    )
    # An acknowledged remote launch still needs a visible exposure warning.
    if public_bind_warning is not None:
        click.echo(public_bind_warning, err=True)
    server = _dashboard_server(request)
    bound_host, actual_port = server.server_address[:2]
    actual_host = bound_host.decode("utf-8") if isinstance(bound_host, bytes) else bound_host
    _write_stdout(f"{TOOL_NAME} dashboard serving at http://{actual_host}:{actual_port}/\n")
    try:
        server.serve_forever()
    # For example, a user pressing Ctrl+C ends the local browser session cleanly.
    except KeyboardInterrupt:
        _write_stdout(f"{TOOL_NAME} dashboard stopped\n")
    finally:
        server.server_close()


def _dashboard_server(request: dashboard_cli._DashboardCliRequest) -> Any:
    """Create the dashboard server for a validated project and port.

    Args:
        request: Launch choices; a missing project root uses the current directory.

    Returns:
        The bound server with the requested project's initial dashboard state.

    Raises:
        click.ClickException: The project is not a directory or the port is outside 0-65535.
    """
    launch_root = Path.cwd()
    project = (request.project_root or launch_root).resolve()
    if not project.is_dir():
        raise click.ClickException(f"Project root is not a directory: {project}")
    if not 0 <= request.port <= 65535:
        raise click.ClickException("--port must be between 0 and 65535.")
    initial_state = dashboard_cli.build_initial_dashboard_state(request, project)
    return create_dashboard_server(
        host=request.host,
        port=request.port,
        launch_root=launch_root,
        initial_state=initial_state,
    )


@_init_command
def init(force: bool) -> None:
    """Create a starter config or canonically regenerate a valid target.

    Args:
        force: Regenerate a valid ``.gruff-py.yaml`` while preserving its
            loaded settings. False leaves any discovered config untouched.

    Raises:
        click.ClickException: The user has an invalid target, an alternate
            config source, or a file that cannot be safely replaced.
    """
    try:
        target = initialise_project_config(Path.cwd(), force=force)
    except ConfigError as exc:
        # A user may have malformed YAML or an authoritative TOML config.
        raise click.ClickException(str(exc)) from exc
    _write_stdout(_init_success_message(target))


@_list_rules_command
def list_rules(rule_format: str, rule_id: str | None) -> None:
    """List gruff rule metadata, or explain one rule when ``rule_id`` is given.

    Args:
        rule_format: Output format - ``json`` for structured output, or ``table``
            / ``text`` for the human-readable table. Ignored for single-rule mode
            where ``table`` coerces to ``text`` since one record has no table.
        rule_id: Optional rule id to render the detail/explain view for.
    """
    registry = RuleRegistry.defaults()
    if rule_id is not None:
        _list_rules_detail(registry, rule_id, rule_format)
        return
    definitions = [rule.definition() for rule in registry.all()]
    if rule_format == "json":
        _write_stdout(json.dumps({"rules": [_rule_payload(d) for d in definitions]}, indent=4))
        _write_stdout("\n")
        return
    _write_stdout(_format_rule_table(definitions))


def _list_rules_detail(registry: RuleRegistry, rule_id: str, rule_format: str) -> None:
    """Render one rule's detailed guidance through the CLI output policy.

    Args:
        registry: Rule collection used to resolve the requested identifier.
        rule_id: Identifier whose metadata and guidance should be displayed.
        rule_format: Requested detail format, with table handled as text by the renderer.

    Returns:
        None; details are sent through the configured CLI output sink.
    """
    list_rules_detail(registry, rule_id, rule_format, _write_stdout)


@_report_command
def report(**kwargs: Any) -> None:
    """Render a gruff-py report to stdout or a file.

    Use this to share a saved scan or inspect findings in the browser with file links rooted at the scanned project.

    Args:
        kwargs: Click-supplied arguments and options.
    """
    request = _analysis_request(kwargs, output_key="report_format", command_name="report")
    output_path = cast(Path | None, kwargs["output_path"])
    analysis_report = _run_analysis_for_cli(request)
    rendered = _render_report(
        analysis_report,
        request.output,
        project_root=analysis_report.machine_context.project_root,
        report_editor_link=request.report_editor_link,
        report_interactive=request.should_render_interactive,
    )
    # A caller who chose an output file gets the report there so it can be opened or shared later.
    if output_path is not None:
        output_path.write_text(rendered)
    else:
        _write_stdout(rendered)
    sys.exit(analysis_report.exit_code)


@_summary_command
def summary(**kwargs: Any) -> None:
    """Print a compact digest of a scan.

    Use this to triage the main issues without reading every finding from the scan.

    Args:
        kwargs: Click-supplied arguments and options.

    Raises:
        click.ClickException: If ``--top`` is less than 1.
    """
    top = cast(int, kwargs["top"])
    summary_format = cast(str, kwargs["summary_format"])
    group_by = cast(str, kwargs["group_by"])
    # The summary needs room for at least one item in each ranked list.
    if top < 1:
        raise click.ClickException("--top must be greater than 0.")
    request = _summary_analysis_request(kwargs, summary_format=summary_format)
    start = time.perf_counter()
    analysis_report = _run_analysis_for_cli(request)
    elapsed_seconds = time.perf_counter() - start
    # CI can read the JSON digest while a terminal user gets the comparable text summary.
    if summary_format == "json":
        _write_stdout(JsonReporter().render_summary(analysis_report))
    else:
        _write_stdout(summary_text(analysis_report, top, elapsed_seconds, group_by=group_by))
    sys.exit(analysis_report.exit_code)


@_metric_calibration_command
def metric_calibration(**kwargs: Any) -> None:
    """Print developer-only complexity metric distributions.

    Args:
        kwargs: Click-supplied arguments and options.

    Raises:
        click.ClickException: If ``--top`` is less than 1.
    """
    top = cast(int, kwargs["top"])
    calibration_format = cast(str, kwargs["calibration_format"])
    if top < 1:
        raise click.ClickException("--top must be greater than 0.")
    report = build_metric_calibration_report(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        no_config=cast(bool, kwargs["no_config"]),
        include_ignored=cast(bool, kwargs["include_ignored"]),
        project_root=Path.cwd(),
    )
    if calibration_format == "json":
        _write_stdout(json.dumps(metric_calibration_payload(report, top=top), indent=4))
        _write_stdout("\n")
    else:
        _write_stdout(render_metric_calibration_text(report, top=top))
    sys.exit(2 if report.has_input_errors() else 0)


@_list_command
def list_commands(
    ctx: click.Context,
    namespace: str | None,
    raw: bool,
    list_format: str,
    short: bool,
) -> None:
    """List available CLI commands in the requested format.

    Args:
        ctx: Active Click context.
        namespace: Optional command namespace prefix to list.
        raw: Whether to print only command names.
        list_format: Output format.
        short: Whether to omit descriptions where supported.
    """
    rows = _command_rows(_root_group(ctx), namespace)
    _write_stdout(_render_command_rows(rows, raw=raw, list_format=list_format, short=short))


@_help_command_decorator
def help_command(ctx: click.Context, command_name: str | None) -> None:
    """Display root help or help for one command.

    Args:
        ctx: Active Click context.
        command_name: Optional command name to inspect.

    Raises:
        click.ClickException: If the requested command is unknown.
    """
    root = _root_group(ctx)
    if command_name is None:
        _write_stdout(ctx.find_root().get_help() + "\n")
        return
    command = root.get_command(ctx, command_name)
    if command is None:
        raise click.ClickException(f'Command "{command_name}" is not defined.')
    with click.Context(command, info_name=command_name, parent=ctx.find_root()) as command_ctx:
        _write_stdout(command.get_help(command_ctx) + "\n")


@_completion_command
def completion(ctx: click.Context, shell: str | None, debug: bool) -> None:
    """Dump the shell completion script.

    Args:
        ctx: Active Click context.
        shell: Optional shell name.
        debug: Whether completion debug logs were requested.

    Raises:
        click.ClickException: If the shell is unsupported or debug mode is requested.
    """
    if debug:
        raise click.ClickException("Completion debug logs are not implemented in gruff-py.")
    resolved_shell = shell or _detect_shell()
    completion_class = get_completion_class(resolved_shell)
    if completion_class is None:
        raise click.ClickException(f'Unsupported shell "{resolved_shell}". Supported shells: bash, fish, zsh.')
    source = completion_class(_root_group(ctx), {}, TOOL_NAME, "_GRUFF_PY_COMPLETE").source()
    _write_stdout(source)
    if not source.endswith("\n"):
        _write_stdout("\n")


@_check_ignore_command
def check_ignore(**kwargs: Any) -> None:
    """Report whether gruff would ignore each path, and why.

    Args:
        kwargs: Click-supplied arguments and options.
    """
    paths = cast(tuple[str, ...], kwargs["paths"])
    config_path = cast(Path | None, kwargs["config_path"])
    no_config = cast(bool, kwargs["no_config"])
    output_format = cast(str, kwargs["check_ignore_format"])
    if not paths:
        click.echo("check-ignore requires at least one path.", err=True)
        sys.exit(2)
    if no_config and config_path is not None:
        click.echo("--no-config cannot be combined with an explicit --config path.", err=True)
        sys.exit(2)
    try:
        verdicts = classify_paths(
            project_root=Path.cwd(),
            paths=paths,
            config_path=config_path,
            no_config=no_config,
        )
    except ConfigError as exc:
        click.echo(str(exc), err=True)
        sys.exit(2)
    if output_format == "json":
        _write_stdout(render_check_ignore_json(verdicts))
    else:
        _write_stdout(render_check_ignore_text(verdicts))
    sys.exit(check_ignore_exit_code(verdicts))


def _analysis_request(
    kwargs: Mapping[str, Any],
    *,
    output_key: str,
    command_name: str,
) -> _AnalysisCliRequest:
    """Collect analysis or report options into one execution request.

    Warn on stderr when the caller uses a superseded option spelling.

    Args:
        kwargs: Parsed Click values, including targets, filters and baseline choices.
        output_key: Option key holding this command's requested report format.
        command_name: Invocation name used when applying configured exit thresholds.

    Returns:
        The request with legacy path spellings resolved and stdin diff text read when requested.
    """
    _warn_superseded_spellings(kwargs)
    return _AnalysisCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        output=OutputFormat(cast(str, kwargs[output_key])),
        fail_on=FailThreshold(cast(str, kwargs["fail_on"])),
        was_fail_on_set_on_cli=was_fail_on_set_on_cli(),
        command_name=command_name,
        report_editor_link=cast(str, kwargs["report_editor_link"]),
        should_render_interactive=cast(bool, kwargs["report_interactive"]),
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        min_severity=cast(str | None, kwargs["min_severity"]),
        include_pillar=cast(tuple[str, ...], kwargs["include_pillar"]),
        exclude_pillar=cast(tuple[str, ...], kwargs["exclude_pillar"]),
        include_rule=cast(tuple[str, ...], kwargs["include_rule"]),
        exclude_rule=cast(tuple[str, ...], kwargs["exclude_rule"]),
        show_rule=cast(tuple[str, ...], kwargs.get("show_rule", ())),
        hide_rule=cast(tuple[str, ...], kwargs.get("hide_rule", ())),
        show_pillar=cast(tuple[str, ...], kwargs.get("show_pillar", ())),
        hide_pillar=cast(tuple[str, ...], kwargs.get("hide_pillar", ())),
        min_confidence=cast("str | None", kwargs.get("min_confidence")),
        fail_on_new=bool(kwargs.get("fail_on_new", False)),
        baseline_path=_first_present_path(kwargs, ("baseline", "baseline_path")),
        generate_baseline_path=_resolve_generate_baseline_path(kwargs),
        migrate_baseline_path=cast(Path | None, kwargs.get("migrate_baseline_path")),
        force_baseline_overwrite=cast(bool, kwargs.get("force_baseline_overwrite", False)),
        should_skip_baseline=cast(bool, kwargs.get("no_baseline", False)),
        diff_mode=_resolved_diff_mode(kwargs),
        diff_patch=_read_diff_patch(cast(str, kwargs.get("diff_mode", ""))),
        since=cast(str, kwargs.get("since", "")),
        changed_ranges=cast("str | None", kwargs.get("changed_ranges")),
        changed_scope=cast(str, kwargs.get("changed_scope", "symbol")),
        strict_config=cast(bool, kwargs.get("strict_config", False)),
        deep_scan_budget=cast(str, kwargs.get("deep_scan_budget", "")),
    )


def _resolved_diff_mode(kwargs: Mapping[str, Any]) -> str:
    """Choose the diff selector to pass to changed-region resolution.

    A --diff-base ref takes precedence over --diff-vs and the --diff mode.

    Args:
        kwargs: Parsed Click options for this invocation.

    Returns:
        The selected ref or diff mode, or an empty string when no diff option has a value.
    """
    for name in ("diff_base", "diff_vs"):
        value = kwargs.get(name)
        if isinstance(value, str) and value:
            return value
    return cast(str, kwargs.get("diff_mode", ""))


def _first_present_path(kwargs: Mapping[str, Any], names: tuple[str, ...]) -> Path | None:
    """Return the first path the user actually gave, in canonical-spelling-first order.

    Args:
        kwargs: Parsed Click options for this invocation.
        names: Option names to try, the family spelling first.

    Returns:
        The path the user named, or None when they named none of them.
    """
    for name in names:
        value = kwargs.get(name)
        if value is not None:
            return cast("Path | None", value)
    return None


def _warn_superseded_spellings(kwargs: Mapping[str, Any]) -> None:
    """Warn for each superseded option with a value, naming its replacement.

    An existing script still runs while stderr tells its maintainer which flag to adopt.

    Args:
        kwargs: Parsed Click options for this invocation.

    Returns:
        None; detected superseded options produce stderr warnings without stopping the run.
    """
    # Check the compatibility spellings the caller may still have in a script or saved command.
    for option_name, replacement in (
        ("baseline_path", "--baseline"),
        ("diff_vs", "--diff-base"),
        ("generate_baseline_path", "--generate-baseline=PATH"),
    ):
        option_value = kwargs.get(option_name)
        # An explicitly empty --diff-vs leaves diff selection unchanged, so it needs no migration warning.
        if option_value in (None, ""):
            continue
        typed = "--" + option_name.replace("_", "-")
        click.echo(
            f"{typed} is superseded by {replacement} and behaves identically; the old spelling is going away.",
            err=True,
        )


def _resolve_generate_baseline_path(kwargs: Mapping[str, Any]) -> Path | None:
    """Return where a generated baseline is written, or None when the user asked for none.

    The canonical --generate-baseline destination takes precedence over the supported --generate-baseline-path spelling.

    Args:
        kwargs: Parsed Click options for this invocation.

    Returns:
        The destination path, or None when neither spelling was used.
    """
    canonical = cast(Path | None, kwargs.get("generate_baseline"))
    if canonical is not None:
        return canonical
    return cast(Path | None, kwargs.get("generate_baseline_path"))


def _summary_analysis_request(
    kwargs: Mapping[str, Any],
    *,
    summary_format: str,
) -> _AnalysisCliRequest:
    """Build a summary scan request without baseline or diff filtering.

    Args:
        kwargs: Parsed targets, config choices and discovery options for the summary.
        summary_format: Selects JSON output for json and text output otherwise.

    Returns:
        A request with finding-based failure disabled and no baseline or diff constraints.
    """
    return _AnalysisCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        output=OutputFormat.JSON if summary_format == "json" else OutputFormat.TEXT,
        fail_on=FailThreshold.NONE,
        was_fail_on_set_on_cli=True,
        command_name="summary",
        report_editor_link="none",
        should_render_interactive=False,
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        min_severity=None,
        include_pillar=(),
        exclude_pillar=(),
        include_rule=(),
        exclude_rule=(),
        baseline_path=None,
        generate_baseline_path=None,
        migrate_baseline_path=None,
        force_baseline_overwrite=False,
        should_skip_baseline=True,
        diff_mode="",
        diff_patch="",
        since="",
        changed_ranges=None,
        changed_scope="symbol",
        strict_config=cast(bool, kwargs.get("strict_config", False)),
        deep_scan_budget=cast(str, kwargs.get("deep_scan_budget", "")),
    )


def _dashboard_request(kwargs: Mapping[str, Any]) -> dashboard_cli._DashboardCliRequest:
    """Turn parsed Click values into the user's dashboard launch request.

    Args:
        kwargs: Parsed Click options. An unset project_root selects the launch directory.
            An unset config_path allows normal discovery when config loading is enabled.

    Returns:
        Startup request; empty paths mean scan the selected project root.
    """
    return dashboard_cli._DashboardCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        project_root=cast(Path | None, kwargs["project_root"]),
        host=cast(str, kwargs["host"]),
        port=cast(int, kwargs["port"]),
        fail_on=cast(str, kwargs["fail_on"]),
        was_fail_on_set_on_cli=was_fail_on_set_on_cli(),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        should_render_interactive=cast(bool, kwargs["report_interactive"]),
        has_acknowledged_public_bind=cast(bool, kwargs["allow_public"]),
        deep_scan_budget=cast(str, kwargs.get("deep_scan_budget", "")),
    )


def _maybe_prompt_to_init_config(
    config_path: Path | None,
    no_config: bool,
    *,
    project_root: Path | None = None,
) -> None:
    """Offer to write a default .gruff-py.yaml when no configuration is discoverable.

    Offer setup only during an interactive scan of an unconfigured project.
    The prompt and confirmation go to stderr so output such as `--format json` stays parseable.

    Args:
        config_path: Explicit --config path that suppresses the offer, or None to allow discovery.
        no_config: Suppress the offer when the caller has disabled configuration.
        project_root: Scan root to search and write to, or None to use the current working directory.

    Returns:
        None. Writes the default file and announces it on stderr only when the user accepts the prompt.
    """
    # Passing `--config` or `--no-config` already expresses how the caller wants settings handled.
    if config_path is not None or no_config:
        return
    # Quiet or noninteractive commands must run without asking to change the project.
    if _state().is_interaction_disabled or _state().should_suppress_output:
        return
    # A piped invocation has no terminal user to answer the prompt.
    if not sys.stdin.isatty():
        return
    # A scan launched from outside its project should offer setup in the scanned checkout.
    target_root = project_root if project_root is not None else Path.cwd()
    # A project with discoverable settings has already completed setup.
    if existing_config_source(target_root) is not None:
        return
    # Declining the offer lets analysis use defaults without writing anything.
    if not click.confirm(
        "No .gruff-py.yaml found. Generate a default config now?",
        default=False,
        err=True,
    ):
        return
    target = target_root / ".gruff-py.yaml"
    _write_config_file(target, render_default_config_yaml())
    click.echo(_init_success_message(target), nl=False, err=True)


def _write_config_file(path: Path, content: str) -> None:
    """Write the generated configuration and translate filesystem failures for Click.

    Args:
        path: Destination selected for the project's configuration file.
        content: Complete configuration text to write at the destination.

    Returns:
        None; the destination file contains the supplied text after a successful write.

    Raises:
        click.ClickException: The destination cannot be written because of an operating-system error.
    """
    try:
        path.write_text(content)
    except OSError as exc:
        raise click.ClickException(f"Unable to write {path.name}: {exc}") from exc


def _is_same_or_descendant(candidate: Path, ancestor: Path) -> bool:
    """Report whether one directory is another or sits inside it.

    Comparison is by whole path segment, so a sibling folder such as /work/apidocs is never mistaken for something inside /work/api.

    Args:
        candidate: Directory being tested.
        ancestor: Directory that may contain it.

    Returns:
        True when candidate is the ancestor or sits inside it.
    """
    return candidate == ancestor or ancestor in candidate.parents


def _target_outside_launch_directory(paths: Sequence[str]) -> str | None:
    """Name the first of several targets that sits outside the launch directory.

    Multiple targets must stay within the launch directory; the caller refuses any run that violates this policy.

    Args:
        paths: Scan targets as typed on the command line.

    Returns:
        The first outside target as typed, or None if fewer than two were named or all are inside. Paths are normalised for the check.
    """
    # A single target, or none, always has a root the run can report against.
    if len(paths) < 2:
        return None
    working_directory = Path.cwd()
    for raw_path in paths:
        absolute = Path(raw_path)
        # Relative targets face the same containment check as absolute paths, including when .. takes them outside the launch directory.
        if not absolute.is_absolute():
            absolute = working_directory / absolute
        # An outside target violates the launch-directory policy, so the caller must refuse this multi-target run.
        if not _is_same_or_descendant(Path(os.path.normpath(absolute)), working_directory):
            return raw_path
    return None


def _project_root_from_targets(paths: Sequence[str]) -> Path:
    """Pick the directory that every reported path is written relative to.

    Targets outside the launch directory use a containing root; targets inside it keep that directory as the reporting base.

    Args:
        paths: Scan targets as typed on the command line; empty means no target was named, so the launch directory is the project.

    Returns:
        Directory to treat as the project root; never empty.

    Raises:
        click.ClickException: Targets have no shared path root, such as paths on different Windows drives.
    """
    working_directory = Path.cwd()

    # No target was named, so the directory the command ran from is the project.
    if not paths:
        return working_directory

    common: Path | None = None
    # A shared reporting base must contain every target directory.
    for raw_path in paths:
        absolute = Path(raw_path)
        # A single relative target that goes through .. can select a reporting root outside the launch directory.
        if not absolute.is_absolute():
            absolute = working_directory / absolute
        absolute = Path(os.path.normpath(absolute))
        # A missing target contributes its parent, giving discovery a reporting root for a missing-path diagnostic.
        directory = absolute if absolute.is_dir() else absolute.parent

        # The first target sets the starting answer; later ones can only widen it.
        if common is None:
            common = directory
            continue
        while not _is_same_or_descendant(directory, common):
            parent = common.parent
            # Targets on separate drives still have no common directory at the top of either drive.
            if parent == common:
                raise click.ClickException("scan targets do not share a filesystem root")
            common = parent

    # Targets sit inside the launch directory, so it stays the root.
    # Moving the root down to a target's own folder would re-anchor config discovery, ignore patterns, and baseline paths.
    if common is None or _is_same_or_descendant(common, working_directory):
        return working_directory
    return common


def _targets_for_root(project_root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    """Write each relative target as an absolute path from the launch directory when the project root is elsewhere.

    Discovery resolves relative targets from the project root. Anchoring them to the launch directory preserves the paths the caller named.

    Args:
        project_root: Root from which discovery resolves scan targets.
        paths: Scan targets as typed on the command line. An empty tuple leaves discovery to start at the project root.

    Returns:
        The targets unchanged when the root is the launch directory, otherwise each relative target anchored to the launch directory.
    """
    working_directory = Path.cwd()
    # When the launch directory is the project root, discovery already resolves relative targets from the caller's directory.
    if project_root == working_directory:
        return paths
    return tuple(raw_path if Path(raw_path).is_absolute() else str(working_directory / raw_path) for raw_path in paths)


def _path_for_root(project_root: Path, path: Path | None) -> Path | None:
    """Rewrite a typed file path, such as ``--baseline``, so that read against the project root it names the same file.

    A relative baseline path could name a different file when the launch directory and the baseline store's project root differ.

    Args:
        project_root: Root chosen by ``_project_root_from_targets``.
        path: The path as typed on the command line, or None when the flag was not given.

    Returns:
        The input when absent, absolute, or launched from the root; otherwise the same file relative to the root or absolute across drives.
    """
    working_directory = Path.cwd()
    # An unset path, an absolute path, or a path already relative to the project root can go straight to the baseline store.
    if path is None or path.is_absolute() or project_root == working_directory:
        return path
    try:
        return Path(os.path.relpath(working_directory / path, project_root))
    except ValueError:
        # Windows cannot relate paths on two drives; the absolute path still names the right file.
        return working_directory / path


def _run_analysis_for_cli(request: _AnalysisCliRequest) -> AnalysisReport:
    """Run a prepared terminal scan and return a result for the chosen reporter.
    Configuration warnings go to stderr so machine readers can parse stdout separately.

    Args:
        request: Targets, execution and display selectors, output mode, and baseline and diff settings to apply.

    Returns:
        The analysis report, or in JSON mode a refusal report for a multi-target launch-directory violation or a ConfigError.

    Raises:
        SystemExit: A handled target or configuration error prevents a non-JSON run; the exit code is 2.
        click.BadParameter: A supplied display or execution pillar is not recognized.
        ValueError: The parsed minimum Python version is below 3.11, even in JSON mode.
    """
    # Presentation flags control what readers see without changing the checks, score or verdict.
    display_filter = FindingDisplayFilter(
        min_severity=Severity(request.min_severity) if request.min_severity is not None else None,
        include_pillars=_parse_pillar_values("--show-pillar", request.show_pillar),
        exclude_pillars=_parse_pillar_values("--hide-pillar", request.hide_pillar),
        include_rules=_split_repeated_csv(request.show_rule),
        exclude_rules=_split_repeated_csv(request.hide_rule),
    )
    outside_target = _target_outside_launch_directory(request.paths)
    # Multiple targets must stay inside the launch directory; JSON returns a refusal report and other formats exit 2 after stderr.
    if outside_target is not None:
        message = (
            f"target {outside_target!r} is outside the launch directory; "
            "gruff-py analyses several targets only from a directory that contains them all"
        )
        # An automation client still gets the standard envelope when the scan cannot start.
        if request.output is OutputFormat.JSON:
            return _refused_run_report(request, RunDiagnostic(type="target-error", message=message), Path.cwd())
        click.echo(message, err=True)
        raise SystemExit(2)
    project_root = _project_root_from_targets(request.paths)
    _maybe_prompt_to_init_config(request.config_path, request.should_skip_config, project_root=project_root)
    try:
        report = run_analysis(
            AnalysisRunRequest(
                paths=_targets_for_root(project_root, request.paths),
                config_path=request.config_path,
                no_config=request.should_skip_config,
                output=request.output,
                fail_threshold=request.fail_on,
                config_severity_command=("" if request.was_fail_on_set_on_cli else request.command_name),
                include_ignored=request.should_include_ignored,
                project_root=project_root,
                display_filter=display_filter,
                baseline=BaselineOptions(
                    apply_path=_path_for_root(project_root, request.baseline_path),
                    generate_path=_path_for_root(project_root, request.generate_baseline_path),
                    disabled=request.should_skip_baseline,
                    migrate_path=_path_for_root(project_root, request.migrate_baseline_path),
                    force_overwrite=request.force_baseline_overwrite,
                ),
                diff_mode=request.diff_mode,
                diff_patch=request.diff_patch,
                since=request.since,
                changed_ranges=request.changed_ranges,
                changed_scope=request.changed_scope,
                execution_include_rules=_split_repeated_csv(request.include_rule),
                execution_exclude_rules=_split_repeated_csv(request.exclude_rule),
                execution_include_pillars=tuple(pillar.value for pillar in _parse_pillar_values("--include-pillar", request.include_pillar)),
                execution_exclude_pillars=tuple(pillar.value for pillar in _parse_pillar_values("--exclude-pillar", request.exclude_pillar)),
                strict_config=request.strict_config,
                deep_scan_budget=request.deep_scan_budget,
                min_confidence=Confidence(request.min_confidence or Confidence.LOW),
                fail_on_new=request.fail_on_new,
            )
        )
    except ConfigError as exc:
        # A YAML file with the wrong schema version can be returned as a structured refusal to JSON callers.
        if request.output is OutputFormat.JSON:
            return _config_error_report(request, exc, project_root)
        # Exit 1 is reserved for completed runs that meet the findings gate; configuration failures remain distinguishable with exit 2.
        click.echo(str(exc), err=True)
        raise SystemExit(2) from exc
    _echo_config_warnings(report)
    return report


def _echo_config_warnings(report: AnalysisReport) -> None:
    """Echo configuration warnings to stderr so report output on stdout stays separate.

    Args:
        report: Analysis result containing the configuration warnings to display.

    Returns:
        None. Writes each warning to stderr unless quiet or silent mode suppresses output.
    """
    if _state().should_suppress_output:
        return
    for warning in report.config_warnings:
        click.echo(f"Warning: {warning}", err=True)


def _config_error_report(request: _AnalysisCliRequest, exc: ConfigError, project_root: Path) -> AnalysisReport:
    """Build the JSON refusal report for a configuration-load failure.

    The v3 adapter emits a parseable diagnostic instead of stderr prose. Other formats print the error to stderr and exit with code 2.

    Args:
        request: Failed invocation supplying scan targets and output settings. With no explicit config path, the diagnostic has no separate path.
        exc: Configuration error whose message is copied with occurrences of the project-root prefix removed.
        project_root: Root inferred from the scan operands.

    Returns:
        A report containing the configuration diagnostic and exit code 2, with no findings.
    """
    config_path_str = str(request.config_path) if request.config_path is not None else None
    # Remove the project-root prefix so a path under that root can appear as a relative path in the JSON diagnostic.
    message = str(exc).replace(f"{project_root}{os.sep}", "")
    # A user can supply a config outside the project. Name its file without publishing the host directory.
    if request.config_path is not None and request.config_path.is_absolute():
        message = message.replace(str(request.config_path), request.config_path.name)
    return _refused_run_report(request, RunDiagnostic(type="config-error", message=message, path=config_path_str), Path.cwd())


def _refused_run_report(request: _AnalysisCliRequest, diagnostic: RunDiagnostic, project_root: Path) -> AnalysisReport:
    """Create the standard JSON envelope when an invocation fails before scanning.
    Automation gets the diagnostic and exit 2 with no findings or analysed files.

    Args:
        request: Supplies the original paths, output format and gate. An omitted explicit config leaves no config location to report.
        diagnostic: The one run-invalidating diagnostic that explains the refusal.
        project_root: Root for display paths in the refusal.

    Returns:
        A report with no findings, nothing discovered, the diagnostic, and exit code 2.
    """
    config_path_str = str(request.config_path) if request.config_path is not None else None
    return AnalysisReport(
        tool_version=VERSION,
        requested_paths=request.paths,
        format=request.output.value,
        fail_on=request.fail_on.value,
        files_discovered=0,
        files_parsed=0,
        ignored_paths=(),
        missing_paths=(),
        diagnostics=(diagnostic,),
        findings=(),
        exit_code=2,
        config_path=config_path_str,
        machine_context=MachineReportContext(project_root=str(project_root)),
    )


def _read_diff_patch(diff_mode: str) -> str:
    """Read a diff from standard input only when the selector requests it.

    Args:
        diff_mode: The literal - consumes stdin; other selectors leave stdin untouched.

    Returns:
        All stdin text for -, or an empty string for any other selector.
    """
    if diff_mode != "-":
        return ""
    return sys.stdin.read()


def _render_report(
    report: AnalysisReport,
    output: OutputFormat,
    *,
    project_root: str,
    report_editor_link: str,
    report_interactive: bool,
) -> str:
    """Render an analysis report in the selected CLI output format.

    Args:
        report: Completed analysis or refusal report supplied to the format-specific reporter.
        output: Reporter format to select for the returned text.
        project_root: Root used to resolve source links in the HTML report.
        report_editor_link: Editor-link style used by the HTML reporter.
        report_interactive: Whether the HTML report should include interactive controls.

    Returns:
        The selected reporter's complete serialized report.
    """
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


def _init_success_message(config_path: Path) -> str:
    """Describe the configuration just written and the next baseline command.

    Args:
        config_path: Destination to identify in the successful initialization message.

    Returns:
        Confirmation and baseline guidance with a trailing newline.
    """
    return (
        f"Wrote {config_path}\n\n"
        "Next: after reviewing current findings, run:\n"
        f"  {TOOL_NAME} analyse . --generate-baseline --fail-on none\n"
        "Future analyse/report runs auto-apply gruff-baseline.json; "
        f"use `{TOOL_NAME} analyse . --no-baseline` to audit without it.\n"
    )


_LEGACY_NESTED_FALSE_POSITIVE_RULE_IDS = frozenset(
    {
        "correctness.substring-vocabulary-match",
        "correctness.unsafe-numeric-coercion",
        "dead-code.exported-but-unreferenced",
        "design.runtime-sys-path-mutation",
        "naming.abbreviation",
        "security.unsanitized-markdown-interpolation",
        "security.weak-crypto",
        "test-quality.static-analysis-redundant-test",
    }
)


def _rule_payload(definition: RuleDefinition) -> dict[str, Any]:
    """Build a catalogue entry while preserving legacy false-positive metadata.

    Args:
        definition: Rule whose native defaults, thresholds and documentation are being listed.

    Returns:
        Listing fields with nested legacy metadata only for the retained legacy rule identifiers.
    """
    documentation = documentation_for_rule(definition.id)
    documentation_payload = documentation.to_payload()
    false_positive_shapes_payload = documentation_payload.get("falsePositiveShapes", [])
    # Legacy catalogue consumers retain the 0.5 nested envelope; the canonical false-positive metadata is top-level.
    if definition.id not in _LEGACY_NESTED_FALSE_POSITIVE_RULE_IDS:
        documentation_payload.pop("falsePositiveShapes", None)
    return {
        "id": definition.id,
        "name": definition.name,
        "pillar": definition.pillar.value,
        "tier": definition.tier.value,
        "defaultSeverity": definition.default_severity.value,
        "confidence": definition.confidence.value,
        "defaultEnabled": definition.default_enabled,
        **definition.listing_threshold_payload(),
        "options": dict(definition.default_options),
        "description": definition.get_description(),
        **({"falsePositiveShapes": false_positive_shapes_payload} if documentation.false_positive_shapes else {}),
        "documentation": documentation_payload,
    }


def _format_rule_table(definitions: list[RuleDefinition]) -> str:
    """Lay out rule defaults as an aligned, human-readable table.

    Args:
        definitions: Nonempty rule list in the order the rows should appear.

    Returns:
        A table with headers, separators and one row per rule, ending with a newline.
    """
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
    widths = [max(len(headers[index]), *(len(row[index]) for row in rows)) for index in range(len(headers))]
    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return "\n".join(lines) + "\n"


def _split_repeated_csv(values: tuple[str, ...]) -> tuple[str, ...]:
    """Combine repeated comma-separated options without blanks or duplicates.

    Args:
        values: Option occurrences whose comma-separated items should be combined.

    Returns:
        Trimmed nonempty items in first-seen order, or an empty tuple when none remain.
    """
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            stripped = item.strip()
            if stripped:
                items.append(stripped)
    return tuple(dict.fromkeys(items))


def _parse_pillar_values(option: str, values: tuple[str, ...]) -> tuple[Pillar, ...]:
    """Resolve repeated pillar options and identify invalid values for Click.

    Args:
        option: Displayed option name to attach to a validation error.
        values: Repeated, possibly comma-separated pillar values from the command line.

    Returns:
        Unique pillars in first-seen order, or an empty tuple when no nonblank items remain.

    Raises:
        click.BadParameter: An item is not a supported pillar value.
    """
    parsed: list[Pillar] = []
    valid = sorted(p.value for p in Pillar)
    for raw in _split_repeated_csv(values):
        try:
            parsed.append(Pillar(raw))
        except ValueError as exc:
            raise click.BadParameter(
                f"invalid pillar {raw!r} (choose from {', '.join(valid)})",
                param_hint=option,
            ) from exc
    return tuple(parsed)


def _write_stdout(text: str) -> None:
    """Write CLI text unless quiet or silent output policy suppresses it.

    Args:
        text: Already-rendered output to write verbatim, including any needed newline.

    Returns:
        None; permitted output is written to stdout.
    """
    if not _state().should_suppress_output:
        sys.stdout.write(text)


def _root_group(ctx: click.Context) -> click.Group:
    """Find the root command group from a nested Click invocation.

    Args:
        ctx: Active context whose root command is needed for command discovery or help.

    Returns:
        The root Click group.

    Raises:
        click.ClickException: The root command is not a group.
    """
    command = ctx.find_root().command
    if not isinstance(command, click.Group):
        raise click.ClickException("Root command is not a command group.")
    return command


def _command_rows(group: click.Group, namespace: str | None) -> list[tuple[str, str]]:
    """Collect visible command names and short help for an active invocation.

    Args:
        group: Root group to enumerate using the current Click context.
        namespace: Required name prefix; None or an empty string admits every visible command.

    Returns:
        Name/help pairs in the group's listing order, excluding hidden commands.
    """
    rows: list[tuple[str, str]] = []
    for name in group.list_commands(click.get_current_context()):
        if namespace is not None and not name.startswith(namespace):
            continue
        command = group.commands[name]
        if command.hidden:
            continue
        rows.append((name, command.get_short_help_str(limit=100)))
    return rows


def _render_command_rows(
    rows: list[tuple[str, str]],
    *,
    raw: bool,
    list_format: str,
    short: bool,
) -> str:
    """Choose the command-list renderer, with raw names taking precedence.

    Args:
        rows: Visible command names and short descriptions in listing order.
        raw: When true, emit names only regardless of the other rendering choices.
        list_format: Selects json, xml or md; other values use the text renderer.
        short: Suppresses descriptions in Markdown and text output only.

    Returns:
        The rendered command listing. With no rows, raw mode returns an empty string and other formats keep their heading or envelope.
    """
    if raw:
        return "".join(f"{name}\n" for name, _help in rows)
    if list_format == "json":
        return _command_rows_json(rows)
    if list_format == "xml":
        return _command_rows_xml(rows)
    if list_format == "md":
        return _command_rows_markdown(rows, short)
    return _command_rows_text(rows, short)


def _command_rows_json(rows: list[tuple[str, str]]) -> str:
    """Serialize command names and descriptions in the JSON listing envelope.

    Args:
        rows: Ordered name/description pairs; an empty list produces an empty commands array.

    Returns:
        Indented JSON with a trailing newline.
    """
    return (
        json.dumps(
            {"commands": [{"name": name, "description": help_text} for name, help_text in rows]},
            indent=4,
        )
        + "\n"
    )


def _command_rows_xml(rows: list[tuple[str, str]]) -> str:
    """Serialize command names and help as escaped XML elements.

    Args:
        rows: Ordered name/description pairs; an empty list leaves the commands element empty.

    Returns:
        A commands element containing the escaped entries and ending with a newline.
    """
    commands = "".join(f'<command name="{_xml_escape(name)}">{_xml_escape(help_text)}</command>' for name, help_text in rows)
    return f"<commands>{commands}</commands>\n"


def _command_rows_markdown(rows: list[tuple[str, str]], short: bool) -> str:
    """Render visible commands as a Markdown list under the CLI heading.

    Args:
        rows: Ordered command names and descriptions; an empty list retains just the heading.
        short: Omits descriptions when true; empty descriptions are also omitted.

    Returns:
        The heading and command bullets with a trailing newline.
    """
    lines = ["# gruff commands", ""]
    for name, help_text in rows:
        lines.append(f"- `{name}`" if short or not help_text else f"- `{name}` - {help_text}")
    return "\n".join(lines) + "\n"


def _command_rows_text(rows: list[tuple[str, str]], short: bool) -> str:
    """Render visible commands as aligned terminal text.

    Args:
        rows: Ordered command names and descriptions; an empty list retains just the heading.
        short: Omits descriptions when true while keeping the command names.

    Returns:
        The heading and aligned rows with a trailing newline.
    """
    width = max((len(name) for name, _help in rows), default=0)
    lines = ["Available commands:"]
    for name, help_text in rows:
        lines.append(f"  {name:<{width}}  {'' if short else help_text}".rstrip())
    return "\n".join(lines) + "\n"


def _detect_shell() -> str:
    """Choose the shell name for completion from the launch environment.

    Returns:
        The basename of SHELL, falling back to bash when that basename is empty.
    """
    shell = os.environ.get("SHELL", "")
    name = Path(shell).name
    return name or "bash"


def _xml_escape(value: str) -> str:
    """Escape text used in double-quoted XML attributes and element content.

    Args:
        value: Unescaped command name or help text to include in the XML listing.

    Returns:
        Text with ampersands, double quotes and angle brackets replaced by XML entities.
    """
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


if __name__ == "__main__":
    main()
