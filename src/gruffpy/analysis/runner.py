"""End-to-end pipeline (`run_analysis`) shared by `gruff-py analyse` and dashboard scans."""

from pathlib import Path

from gruffpy.analysis.baseline import (
    BaselineError,
    BaselineOptions,
    BaselineReport,
    apply_baseline,
    default_baseline_path,
    generate_baseline,
)
from gruffpy.analysis.report import AnalysisReport, ReportExtensions
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
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.suppression.filter import apply_suppressions
from gruffpy.suppression.parser import ParsedSuppressions, parse_suppressions
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
    baseline: BaselineOptions | None = None,
) -> AnalysisReport:
    """Run the end-to-end analysis pipeline and return a single ``AnalysisReport``.

    Pipeline order: load config, discover and parse sources, parse inline
    suppressions, run every enabled rule, synthesise composite findings,
    apply suppressions again (in case composites are suppressed), filter
    sensitive-data allowed previews, compute scores, derive the exit code,
    and apply the display filter.

    Args:
        paths: CLI-supplied paths; empty tuple is reported as ``(".",)``.
        config_path: Explicit YAML/TOML config path, or ``None`` to use auto-discovery.
        no_config: When true, skip auto-loading the default config file.
        output: Requested output format (recorded on the report).
        fail_threshold: Severity that determines the non-zero exit code.
        include_ignored: When true, scan paths normally excluded by .gitignore and defaults.
        project_root: Resolved project root used for path display and discovery.
        display_filter: Reporter-side filter for ``--min-severity`` / pillar / rule.
        baseline: Baseline apply/generate/disable selection.

    Returns:
        Fully-populated report ready to be handed to a reporter.
    """
    baseline_options = baseline if baseline is not None else BaselineOptions()
    registry = RuleRegistry.defaults()
    config, config_loaded_from, diagnostics = _load_analysis_config(
        project_root=project_root,
        config_path=config_path,
        no_config=no_config,
        registry=registry,
    )

    discovery_result, units, files_parsed, parse_diagnostics = _discover_and_parse_sources(
        project_root=project_root,
        paths=paths,
        include_ignored=include_ignored,
        config=config,
    )
    diagnostics.extend(_missing_path_diagnostics(discovery_result.missing_paths))
    diagnostics.extend(parse_diagnostics)

    context = RuleContext(project_root=str(project_root), config=config)
    suppressions_by_file = _parse_suppressions(units, registry)
    diagnostics.extend(_suppression_diagnostics(suppressions_by_file))
    findings = _collect_findings(
        registry=registry,
        units=units,
        context=context,
        config=config,
        suppressions_by_file=suppressions_by_file,
    )
    baseline_report = _handle_baseline(
        project_root=project_root,
        findings=findings,
        diagnostics=diagnostics,
        options=baseline_options,
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
        extensions=ReportExtensions(baseline=baseline_report),
    )


def _discover_and_parse_sources(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    include_ignored: bool,
    config: AnalysisConfig,
) -> tuple[SourceDiscoveryResult, list[AnalysisUnit], int, list[RunDiagnostic]]:
    discovery = SourceDiscovery(project_root)
    discovery_result = discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )
    units, files_parsed, parse_diagnostics = _parse_sources(discovery_result.files)
    return discovery_result, units, files_parsed, parse_diagnostics


def _collect_findings(
    *,
    registry: RuleRegistry,
    units: list[AnalysisUnit],
    context: RuleContext,
    config: AnalysisConfig,
    suppressions_by_file: dict[str, ParsedSuppressions],
) -> list[Finding]:
    findings = registry.analyse(units, context)
    findings = apply_suppressions(findings, suppressions_by_file)
    findings = CompositeFindingFactory().synthesise(findings)
    findings = apply_suppressions(findings, suppressions_by_file)
    findings = _filter_allowed_secret_previews(findings, config)
    findings.sort(
        key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message)
    )
    return findings


def _handle_baseline(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    options: BaselineOptions,
) -> BaselineReport | None:
    conflict = _baseline_option_conflict(options)
    if conflict is not None:
        diagnostics.append(conflict)
        return None
    if options.generate_path is not None:
        return _generate_baseline_safely(
            project_root=project_root,
            findings=findings,
            diagnostics=diagnostics,
            path=options.generate_path,
        )
    if options.disabled:
        return None
    return _apply_baseline_if_present(
        project_root=project_root,
        findings=findings,
        diagnostics=diagnostics,
        explicit_path=options.apply_path,
    )


def _baseline_option_conflict(options: BaselineOptions) -> RunDiagnostic | None:
    if options.generate_path is not None and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message="--baseline and --generate-baseline are mutually exclusive.",
        )
    if options.disabled and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message="--no-baseline cannot be combined with --baseline.",
            path=str(options.apply_path),
        )
    return None


def _generate_baseline_safely(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    path: Path,
) -> BaselineReport | None:
    try:
        return generate_baseline(project_root=project_root, path=path, findings=findings)
    except BaselineError as exc:
        diagnostics.append(RunDiagnostic(type="baseline-error", message=str(exc), path=str(path)))
        return None


def _apply_baseline_if_present(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    explicit_path: Path | None,
) -> BaselineReport | None:
    selected_path, source = _resolve_baseline_selection(project_root, explicit_path)
    if selected_path is None:
        return None
    try:
        result = apply_baseline(
            project_root=project_root,
            path=selected_path,
            findings=findings,
            source=source,
        )
    except BaselineError as exc:
        diagnostics.append(
            RunDiagnostic(type="baseline-error", message=str(exc), path=str(selected_path))
        )
        return None
    findings[:] = result.findings
    return result.report


def _resolve_baseline_selection(
    project_root: Path, explicit_path: Path | None
) -> tuple[Path | None, str]:
    if explicit_path is not None:
        return explicit_path, "explicit"
    default_path = default_baseline_path(project_root)
    if not default_path.is_file():
        return None, "default"
    return Path(default_path.name), "default"


def _load_analysis_config(
    *,
    project_root: Path,
    config_path: Path | None,
    no_config: bool,
    registry: RuleRegistry,
) -> tuple[AnalysisConfig, str | None, list[RunDiagnostic]]:
    config = AnalysisConfig.from_registry(registry)
    if no_config and config_path is not None:
        return (
            config,
            None,
            [
                RunDiagnostic(
                    type="config-error",
                    message="--no-config cannot be combined with an explicit --config path.",
                )
            ],
        )
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


def _parse_suppressions(
    units: list[AnalysisUnit],
    registry: RuleRegistry,
) -> dict[str, ParsedSuppressions]:
    known_rule_ids = {rule.definition().id for rule in registry.all()}
    known_rule_ids.add(CompositeFindingFactory.GOD_METHOD_RULE_ID)
    return {
        unit.file.display_path: parse_suppressions(
            unit.source,
            known_rule_ids=frozenset(known_rule_ids),
        )
        for unit in units
        if unit.source
    }


def _suppression_diagnostics(
    suppressions_by_file: dict[str, ParsedSuppressions],
) -> list[RunDiagnostic]:
    diagnostics: list[RunDiagnostic] = []
    for file_path, suppressions in suppressions_by_file.items():
        diagnostics.extend(
            RunDiagnostic(
                type=diagnostic.type,
                message=diagnostic.message,
                file_path=file_path,
                line=diagnostic.line,
            )
            for diagnostic in suppressions.diagnostics
        )
    return diagnostics


def compute_exit_code(
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    fail_threshold: FailThreshold,
) -> int:
    """Derive the CLI exit code from the analysis outcome.

    Exit code 2 (diagnostics) wins over 1 (findings) - a parse error
    surfaces even when the project is otherwise clean.

    Args:
        findings: All findings from the run (post-suppression).
        diagnostics: Run-level diagnostics (config errors, parse failures, missing paths).
        fail_threshold: Severity threshold from ``--fail-on``.

    Returns:
        ``2`` when diagnostics exist, ``1`` when any finding meets the
        threshold, otherwise ``0``.
    """
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
