"""End-to-end pipeline (`run_analysis`) shared by `gruff-py analyse` and dashboard scans."""

from pathlib import Path

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.pillar import Pillar
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.composite_finding_factory import CompositeFindingFactory
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.source.discovery import SourceDiscovery
from gruffpy.source.source_file import SourceFile
from gruffpy.version import VERSION


def run_analysis(
    *,
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    output: OutputFormat,
    fail_threshold: FailThreshold,
    include_ignored: bool,
    project_root: Path,
    display_filter: FindingDisplayFilter,
) -> AnalysisReport:
    registry = RuleRegistry.defaults()
    config, config_loaded_from, diagnostics = _load_analysis_config(
        project_root=project_root,
        config_path=config_path,
        no_config=no_config,
        registry=registry,
    )

    discovery = SourceDiscovery(project_root)
    discovery_result = discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )
    diagnostics.extend(_missing_path_diagnostics(discovery_result.missing_paths))

    units, files_parsed, parse_diagnostics = _parse_sources(discovery_result.files)
    diagnostics.extend(parse_diagnostics)

    context = RuleContext(project_root=str(project_root), config=config)
    findings = registry.analyse(units, context)
    findings = CompositeFindingFactory().synthesise(findings)
    findings = _filter_allowed_secret_previews(findings, config)
    findings.sort(
        key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message)
    )
    score = ScoreCalculator().calculate(findings)

    exit_code = compute_exit_code(findings, diagnostics, fail_threshold)
    display_findings = display_filter.filter_findings(findings)

    return AnalysisReport(
        tool_version=VERSION,
        requested_paths=tuple(paths) if paths else (".",),
        format=output.value,
        fail_on=fail_threshold.value,
        files_discovered=len(discovery_result.files),
        files_parsed=files_parsed,
        ignored_paths=discovery_result.ignored_paths,
        missing_paths=discovery_result.missing_paths,
        diagnostics=tuple(diagnostics),
        findings=tuple(display_findings),
        exit_code=exit_code,
        config_path=config_loaded_from,
        score=score,
        filters=display_filter,
    )


def _load_analysis_config(
    *,
    project_root: Path,
    config_path: Path | None,
    no_config: bool,
    registry: RuleRegistry,
) -> tuple[AnalysisConfig, str | None, list[RunDiagnostic]]:
    config = AnalysisConfig.from_registry(registry)
    if no_config:
        return config, None, []

    loader = ConfigLoader(project_root, config)
    try:
        loaded_config, source = loader.load(config_path)
    except ConfigError as exc:
        return config, None, [RunDiagnostic(type="config-error", message=str(exc))]

    return loaded_config, str(source) if source is not None else None, []


def _parse_sources(
    source_files: tuple[SourceFile, ...],
) -> tuple[list[AnalysisUnit], int, list[RunDiagnostic]]:
    parser = PythonFileParser()
    units: list[AnalysisUnit] = []
    diagnostics: list[RunDiagnostic] = []
    files_parsed = 0

    for source_file in source_files:
        unit = parser.parse(source_file)
        units.append(unit)
        if not unit.has_parse_errors():
            files_parsed += 1
            continue
        diagnostics.extend(
            RunDiagnostic(
                type="parse-error",
                message=diagnostic.message,
                file_path=source_file.display_path,
                line=diagnostic.line,
            )
            for diagnostic in unit.diagnostics
        )

    return units, files_parsed, diagnostics


def _missing_path_diagnostics(missing_paths: tuple[str, ...]) -> list[RunDiagnostic]:
    return [
        RunDiagnostic(type="missing-path", message="path not found", path=missing)
        for missing in missing_paths
    ]


def compute_exit_code(
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


def _filter_allowed_secret_previews(
    findings: list[Finding],
    config: AnalysisConfig,
) -> list[Finding]:
    if not config.allowed_secret_previews:
        return findings
    allowed = set(config.allowed_secret_previews)
    return [
        finding
        for finding in findings
        if (
            finding.pillar != Pillar.SENSITIVE_DATA
            or not isinstance(finding.metadata.get("preview"), str)
            or finding.metadata["preview"] not in allowed
        )
    ]
