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
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.composite_finding_factory import CompositeFindingFactory
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.source.discovery import SourceDiscovery
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
    config = AnalysisConfig.from_registry(registry)
    diagnostics: list[RunDiagnostic] = []
    config_loaded_from: str | None = None

    if not no_config:
        loader = ConfigLoader(project_root, config)
        try:
            config, source = loader.load(config_path)
            if source is not None:
                config_loaded_from = str(source)
        except ConfigError as exc:
            diagnostics.append(RunDiagnostic(type="config-error", message=str(exc)))

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
            for diagnostic in unit.diagnostics:
                diagnostics.append(
                    RunDiagnostic(
                        type="parse-error",
                        message=diagnostic.message,
                        file_path=source_file.display_path,
                        line=diagnostic.line,
                    )
                )
        else:
            files_parsed += 1
        units.append(unit)

    context = RuleContext(project_root=str(project_root), config=config)
    findings = registry.analyse(units, context)
    findings = CompositeFindingFactory().synthesise(findings)
    findings = _filter_allowed_secret_previews(findings, config)
    findings.sort(
        key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message)
    )
    score = ScoreCalculator().calculate(findings)

    exit_code = compute_exit_code(findings, diagnostics, fail_threshold)
    display_findings = display_filter.apply(findings)

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
