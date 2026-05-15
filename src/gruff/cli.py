"""Click-based CLI entry point for `gruff`."""

import shlex
import sys
from pathlib import Path

import click

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
from gruff.version import VERSION


@click.group()
@click.version_option(version=VERSION, prog_name="gruff")
def main() -> None:
    """gruff — Python project quality analyser."""


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a config file (defaults to ./pyproject.toml).",
)
@click.option("--no-config", is_flag=True, default=False, help="Skip loading any config file.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice([f.value for f in OutputFormat]),
    default="text",
    help="Output format.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailThreshold]),
    default="error",
    help="Severity at which to set non-zero exit code.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Walk into normally-ignored directories.",
)
@click.option(
    "--min-severity",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Minimum severity to display in the selected report format.",
)
@click.option(
    "--include-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Only display findings for this pillar. Repeat for multiple pillars.",
)
@click.option(
    "--exclude-pillar",
    multiple=True,
    type=click.Choice([p.value for p in Pillar]),
    help="Hide findings for this pillar. Repeat for multiple pillars.",
)
@click.option(
    "--include-rule",
    multiple=True,
    help="Only display findings for this rule id. Repeat or pass comma-separated values.",
)
@click.option(
    "--exclude-rule",
    multiple=True,
    help="Hide findings for this rule id. Repeat or pass comma-separated values.",
)
@click.option(
    "--report-editor-link",
    type=click.Choice(["none", "vscode", "phpstorm"]),
    default="none",
    help="Editor link style for HTML file:line references.",
)
@click.option(
    "--report-interactive",
    is_flag=True,
    default=False,
    help="Render opt-in interactive HTML finding filters.",
)
def analyse(
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    output_format: str,
    fail_on: str,
    include_ignored: bool,
    min_severity: str | None,
    include_pillar: tuple[str, ...],
    exclude_pillar: tuple[str, ...],
    include_rule: tuple[str, ...],
    exclude_rule: tuple[str, ...],
    report_editor_link: str,
    report_interactive: bool,
) -> None:
    """Analyse one or more paths and emit a report."""
    project_root = Path.cwd()
    output = OutputFormat(output_format)
    fail_threshold = FailThreshold(fail_on)
    display_filter = FindingDisplayFilter(
        min_severity=Severity(min_severity) if min_severity is not None else None,
        include_pillars=tuple(Pillar(value) for value in _split_repeated_csv(include_pillar)),
        exclude_pillars=tuple(Pillar(value) for value in _split_repeated_csv(exclude_pillar)),
        include_rules=_split_repeated_csv(include_rule),
        exclude_rules=_split_repeated_csv(exclude_rule),
    )

    report = run_analysis(
        paths=paths,
        config_path=config_path,
        no_config=no_config,
        output=output,
        fail_threshold=fail_threshold,
        include_ignored=include_ignored,
        project_root=project_root,
        display_filter=display_filter,
    )

    sys.stdout.write(
        _render_report(
            report,
            output,
            project_root=str(project_root),
            report_editor_link=report_editor_link,
            report_interactive=report_interactive,
        )
    )
    sys.exit(report.exit_code)


@main.command()
@click.argument("paths", nargs=-1, type=click.Path())
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host interface for the local dashboard server.",
)
@click.option(
    "--port",
    type=int,
    default=8765,
    show_default=True,
    help="Port for the local dashboard server. Use 0 to select an unused port.",
)
@click.option(
    "--project",
    "project_root",
    type=click.Path(path_type=Path),
    default=None,
    help="Project root to analyse from the dashboard.",
)
@click.option(
    "--project-root",
    "project_root",
    type=click.Path(path_type=Path),
    default=None,
    help="Alias for --project.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Initial config file shown in the dashboard controls.",
)
@click.option("--no-config", is_flag=True, default=False, help="Skip loading any config file.")
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice([f.value for f in FailThreshold]),
    default="none",
    help="Initial severity at which analyse scans set non-zero exit code.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Walk into normally-ignored directories.",
)
@click.option(
    "--report-interactive",
    is_flag=True,
    default=False,
    help="Render opt-in interactive HTML finding filters in dashboard scans.",
)
def dashboard(
    paths: tuple[str, ...],
    host: str,
    port: int,
    project_root: Path | None,
    config_path: Path | None,
    no_config: bool,
    fail_on: str,
    include_ignored: bool,
    report_interactive: bool,
) -> None:
    """Serve a local browser dashboard for repeated scans."""
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
    click.echo(f"gruff dashboard serving at http://{actual_host}:{actual_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("gruff dashboard stopped")
    finally:
        server.server_close()


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


def _split_repeated_csv(values: tuple[str, ...]) -> tuple[str, ...]:
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            stripped = item.strip()
            if stripped:
                items.append(stripped)
    return tuple(dict.fromkeys(items))


if __name__ == "__main__":
    main()
