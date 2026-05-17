"""Click-based CLI entry point for `gruff-py`."""

import json
import os
import shlex
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar, cast

import click
from click.shell_completion import get_completion_class

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.runner import run_analysis
from gruffpy.cli_menu import root_menu as _root_menu, should_use_color as _should_use_color
from gruffpy.cli_options import (
    ClickDecorator,
    analyse_command as _analyse_command,
    apply_decorators,
    bind_root_group,
    completion_command as _completion_command,
    dashboard_command as _dashboard_command,
    help_command_decorator as _help_command_decorator,
    list_command as _list_command,
    list_rules_command as _list_rules_command,
    metric_calibration_command as _metric_calibration_command,
    report_command as _report_command,
    summary_command as _summary_command,
)
from gruffpy.cli_state import CliState, state as _state
from gruffpy.command.dashboard_server import DashboardState, create_dashboard_server
from gruffpy.command.metric_calibration import (
    build_metric_calibration_report,
    metric_calibration_payload,
    render_metric_calibration_text,
)
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
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import TOOL_NAME, VERSION

_F = TypeVar("_F", bound=Callable[..., Any])


class GruffGroup(click.Group):
    """Root command group with the custom Symfony-style help screen."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Write the root help menu.

        Args:
            ctx: Active Click context.
            formatter: Click formatter receiving the rendered help.
        """
        formatter.write(_root_menu(ctx))


@dataclass(frozen=True, slots=True)
class _AnalysisCliRequest:
    paths: tuple[str, ...]
    config_path: Path | None
    should_skip_config: bool
    output: OutputFormat
    fail_on: FailThreshold
    report_editor_link: str
    should_render_interactive: bool
    should_include_ignored: bool
    min_severity: str | None
    include_pillar: tuple[str, ...]
    exclude_pillar: tuple[str, ...]
    include_rule: tuple[str, ...]
    exclude_rule: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _DashboardCliRequest:
    paths: tuple[str, ...]
    project_root: Path | None
    host: str
    port: int
    fail_on: str
    config_path: Path | None
    should_skip_config: bool
    should_include_ignored: bool
    should_render_interactive: bool


_ROOT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    cast(ClickDecorator, click.pass_context),
    cast(
        ClickDecorator,
        click.option(
            "-v",
            "--verbose",
            count=True,
            help="Increase message verbosity. Use -v, -vv, or -vvv.",
        ),
    ),
    cast(
        ClickDecorator,
        click.option(
            "-n",
            "--no-interaction",
            is_flag=True,
            help="Do not ask any interactive question.",
        ),
    ),
    cast(
        ClickDecorator,
        click.option("--ansi/--no-ansi", default=None, help="Force or disable ANSI output."),
    ),
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
    cast(
        ClickDecorator,
        click.option(
            "-q",
            "--quiet",
            is_flag=True,
            help="Only errors are displayed. All other output is suppressed.",
        ),
    ),
    cast(ClickDecorator, click.option("--silent", is_flag=True, help="Do not output any message.")),
    cast(
        ClickDecorator,
        click.group(
            name=TOOL_NAME,
            cls=GruffGroup,
            context_settings={"help_option_names": ["-h", "--help"]},
            invoke_without_command=True,
        ),
    ),
)


def _root_command(function: _F) -> _F:
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


@_analyse_command
def analyse(**kwargs: Any) -> None:
    """Run gruff analysis.

    Args:
        kwargs: Click-supplied arguments and options.
    """
    request = _analysis_request(kwargs, output_key="output_format")
    report = _run_analysis_for_cli(request)
    _write_stdout(
        _render_report(
            report,
            request.output,
            project_root=str(Path.cwd()),
            report_editor_link=request.report_editor_link,
            report_interactive=request.should_render_interactive,
        )
    )
    sys.exit(report.exit_code)


@_dashboard_command
def dashboard(**kwargs: Any) -> None:
    """Serve the local gruff-py dashboard.

    Args:
        kwargs: Click-supplied arguments and options.

    Raises:
        click.ClickException: If the project root or port is invalid.
    """
    server = _dashboard_server(_dashboard_request(kwargs))
    bound_host, actual_port = server.server_address[:2]
    actual_host = bound_host.decode("utf-8") if isinstance(bound_host, bytes) else bound_host
    _write_stdout(f"{TOOL_NAME} dashboard serving at http://{actual_host}:{actual_port}/\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _write_stdout(f"{TOOL_NAME} dashboard stopped\n")
    finally:
        server.server_close()


def _dashboard_server(request: _DashboardCliRequest) -> Any:
    launch_root = Path.cwd()
    project = (request.project_root or launch_root).resolve()
    if not project.is_dir():
        raise click.ClickException(f"Project root is not a directory: {project}")
    if request.port < 0 or request.port > 65535:
        raise click.ClickException("--port must be between 0 and 65535.")

    initial_state = DashboardState(
        project=str(project),
        paths=" ".join(shlex.quote(path) for path in (request.paths or (".",))),
        fail_on=request.fail_on,
        config=str(request.config_path) if request.config_path is not None else "",
        no_config=request.should_skip_config,
        include_ignored=request.should_include_ignored,
        report_interactive=request.should_render_interactive,
    )
    return create_dashboard_server(
        host=request.host,
        port=request.port,
        launch_root=launch_root,
        initial_state=initial_state,
    )


@_list_rules_command
def list_rules(rule_format: str) -> None:
    """List gruff rule metadata.

    Args:
        rule_format: Output format, either ``table`` or ``json``.
    """
    definitions = [rule.definition() for rule in RuleRegistry.defaults().all()]
    if rule_format == "json":
        _write_stdout(json.dumps({"rules": [_rule_payload(d) for d in definitions]}, indent=4))
        _write_stdout("\n")
        return
    _write_stdout(_format_rule_table(definitions))


@_report_command
def report(**kwargs: Any) -> None:
    """Render a gruff-py report to stdout or a file.

    Args:
        kwargs: Click-supplied arguments and options.
    """
    request = _analysis_request(kwargs, output_key="report_format")
    output_path = cast(Path | None, kwargs["output_path"])
    analysis_report = _run_analysis_for_cli(request)
    rendered = _render_report(
        analysis_report,
        request.output,
        project_root=str(Path.cwd()),
        report_editor_link=request.report_editor_link,
        report_interactive=request.should_render_interactive,
    )
    if output_path is not None:
        output_path.write_text(rendered)
    else:
        _write_stdout(rendered)
    sys.exit(analysis_report.exit_code)


@_summary_command
def summary(**kwargs: Any) -> None:
    """Print a compact digest of a scan.

    Args:
        kwargs: Click-supplied arguments and options.

    Raises:
        click.ClickException: If ``--top`` is less than 1.
    """
    top = cast(int, kwargs["top"])
    summary_format = cast(str, kwargs["summary_format"])
    if top < 1:
        raise click.ClickException("--top must be greater than 0.")
    analysis_report = _run_analysis_for_cli(
        _summary_analysis_request(kwargs, summary_format=summary_format)
    )
    if summary_format == "json":
        _write_stdout(json.dumps(_summary_payload(analysis_report, top), indent=4))
        _write_stdout("\n")
    else:
        _write_stdout(_summary_text(analysis_report, top))
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
        raise click.ClickException(
            f'Unsupported shell "{resolved_shell}". Supported shells: bash, fish, zsh.'
        )
    source = completion_class(_root_group(ctx), {}, TOOL_NAME, "_GRUFF_PY_COMPLETE").source()
    _write_stdout(source)
    if not source.endswith("\n"):
        _write_stdout("\n")


def _analysis_request(kwargs: Mapping[str, Any], *, output_key: str) -> _AnalysisCliRequest:
    return _AnalysisCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        output=OutputFormat(cast(str, kwargs[output_key])),
        fail_on=FailThreshold(cast(str, kwargs["fail_on"])),
        report_editor_link=cast(str, kwargs["report_editor_link"]),
        should_render_interactive=cast(bool, kwargs["report_interactive"]),
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        min_severity=cast(str | None, kwargs["min_severity"]),
        include_pillar=cast(tuple[str, ...], kwargs["include_pillar"]),
        exclude_pillar=cast(tuple[str, ...], kwargs["exclude_pillar"]),
        include_rule=cast(tuple[str, ...], kwargs["include_rule"]),
        exclude_rule=cast(tuple[str, ...], kwargs["exclude_rule"]),
    )


def _summary_analysis_request(
    kwargs: Mapping[str, Any],
    *,
    summary_format: str,
) -> _AnalysisCliRequest:
    return _AnalysisCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        output=OutputFormat.JSON if summary_format == "json" else OutputFormat.TEXT,
        fail_on=FailThreshold.NONE,
        report_editor_link="none",
        should_render_interactive=False,
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        min_severity=None,
        include_pillar=(),
        exclude_pillar=(),
        include_rule=(),
        exclude_rule=(),
    )


def _dashboard_request(kwargs: Mapping[str, Any]) -> _DashboardCliRequest:
    return _DashboardCliRequest(
        paths=cast(tuple[str, ...], kwargs["paths"]),
        project_root=cast(Path | None, kwargs["project_root"]),
        host=cast(str, kwargs["host"]),
        port=cast(int, kwargs["port"]),
        fail_on=cast(str, kwargs["fail_on"]),
        config_path=cast(Path | None, kwargs["config_path"]),
        should_skip_config=cast(bool, kwargs["no_config"]),
        should_include_ignored=cast(bool, kwargs["include_ignored"]),
        should_render_interactive=cast(bool, kwargs["report_interactive"]),
    )


def _run_analysis_for_cli(request: _AnalysisCliRequest) -> AnalysisReport:
    display_filter = FindingDisplayFilter(
        min_severity=Severity(request.min_severity) if request.min_severity is not None else None,
        include_pillars=tuple(
            Pillar(value) for value in _split_repeated_csv(request.include_pillar)
        ),
        exclude_pillars=tuple(
            Pillar(value) for value in _split_repeated_csv(request.exclude_pillar)
        ),
        include_rules=_split_repeated_csv(request.include_rule),
        exclude_rules=_split_repeated_csv(request.exclude_rule),
    )
    return run_analysis(
        paths=request.paths,
        config_path=request.config_path,
        no_config=request.should_skip_config,
        output=request.output,
        fail_threshold=request.fail_on,
        include_ignored=request.should_include_ignored,
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
    if not _state().should_suppress_output:
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


def _render_command_rows(
    rows: list[tuple[str, str]],
    *,
    raw: bool,
    list_format: str,
    short: bool,
) -> str:
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
    return (
        json.dumps(
            {"commands": [{"name": name, "description": help_text} for name, help_text in rows]},
            indent=4,
        )
        + "\n"
    )


def _command_rows_xml(rows: list[tuple[str, str]]) -> str:
    commands = "".join(
        f'<command name="{_xml_escape(name)}">{_xml_escape(help_text)}</command>'
        for name, help_text in rows
    )
    return f"<commands>{commands}</commands>\n"


def _command_rows_markdown(rows: list[tuple[str, str]], short: bool) -> str:
    lines = ["# gruff commands", ""]
    for name, help_text in rows:
        lines.append(f"- `{name}`" if short or not help_text else f"- `{name}` - {help_text}")
    return "\n".join(lines) + "\n"


def _command_rows_text(rows: list[tuple[str, str]], short: bool) -> str:
    width = max((len(name) for name, _help in rows), default=0)
    lines = ["Available commands:"]
    for name, help_text in rows:
        lines.append(f"  {name:<{width}}  {'' if short else help_text}".rstrip())
    return "\n".join(lines) + "\n"


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
