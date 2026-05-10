"""Click-based CLI entry point for `gruff`."""

import sys
from pathlib import Path

import click

from gruff.analysis.report import AnalysisReport
from gruff.analysis.run_diagnostic import RunDiagnostic
from gruff.config.analysis_config import AnalysisConfig
from gruff.config.exceptions import ConfigError
from gruff.config.loader import ConfigLoader
from gruff.finding.fail_threshold import FailThreshold
from gruff.finding.finding import Finding
from gruff.finding.output_format import OutputFormat
from gruff.parser.python_parser import PythonFileParser
from gruff.reporting.json_reporter import JsonReporter
from gruff.reporting.text_reporter import TextReporter
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.scoring.score_calculator import ScoreCalculator
from gruff.source.discovery import SourceDiscovery
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
def analyse(
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    output_format: str,
    fail_on: str,
    include_ignored: bool,
) -> None:
    """Analyse one or more paths and emit a report."""
    project_root = Path.cwd()
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    diagnostics: list[RunDiagnostic] = []
    config_loaded_from: str | None = None

    if not no_config:
        loader = ConfigLoader(project_root, config)
        target_path = config_path or (project_root / "pyproject.toml")
        try:
            config = loader.load(target_path if config_path else None)
            if target_path.exists():
                config_loaded_from = str(target_path)
        except ConfigError as exc:
            diagnostics.append(RunDiagnostic(type="config-error", message=str(exc)))

    fail_threshold = FailThreshold(fail_on)
    output = OutputFormat(output_format)

    discovery = SourceDiscovery(project_root)
    discovery_result = discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )
    for missing in discovery_result.missing_paths:
        diagnostics.append(
            RunDiagnostic(type="missing-path", message="path not found", path=missing)
        )

    parser = PythonFileParser()
    units = []
    files_parsed = 0
    for source_file in discovery_result.files:
        unit = parser.parse(source_file)
        if unit.has_parse_errors():
            for d in unit.diagnostics:
                diagnostics.append(
                    RunDiagnostic(
                        type="parse-error",
                        message=d.message,
                        file_path=source_file.display_path,
                        line=d.line,
                    )
                )
        else:
            files_parsed += 1
        units.append(unit)

    context = RuleContext(project_root=str(project_root), config=config)
    findings = registry.analyse(units, context)
    score = ScoreCalculator().calculate(findings)

    exit_code = _compute_exit_code(findings, diagnostics, fail_threshold)

    report = AnalysisReport(
        tool_version=VERSION,
        requested_paths=tuple(paths) if paths else (".",),
        format=output.value,
        fail_on=fail_threshold.value,
        files_discovered=len(discovery_result.files),
        files_parsed=files_parsed,
        ignored_paths=discovery_result.ignored_paths,
        missing_paths=discovery_result.missing_paths,
        diagnostics=tuple(diagnostics),
        findings=tuple(findings),
        exit_code=exit_code,
        config_path=config_loaded_from,
        score=score,
    )

    if output is OutputFormat.JSON:
        click.echo(JsonReporter().render(report), nl=False)
    else:
        click.echo(TextReporter().render(report), nl=False)

    sys.exit(exit_code)


def _compute_exit_code(
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    fail_threshold: FailThreshold,
) -> int:
    if diagnostics:
        return 2
    for finding in findings:
        if fail_threshold.is_triggered_by(finding.severity):
            return 1
    return 0


if __name__ == "__main__":
    main()
