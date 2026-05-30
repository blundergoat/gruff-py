"""End-to-end pipeline (`run_analysis`) shared by `gruff-py analyse` and dashboard scans."""

from dataclasses import replace
from pathlib import Path

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import (
    BaselineError,
    BaselineOptions,
    BaselineReport,
    apply_baseline,
    default_baseline_path,
    generate_baseline,
)
from gruffpy.analysis.changed_region import (
    ChangedRegionSet,
    changed_regions_from_git,
    filter_findings_for_changed_regions,
    filter_sources_for_changed_regions,
    parse_explicit_ranges,
    parse_unified_diff,
)
from gruffpy.analysis.report import AnalysisReport, ReportExtensions
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.composite_finding_factory import CompositeFindingFactory
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.suppression.filter import apply_suppressions
from gruffpy.suppression.parser import ParsedSuppressions, parse_suppressions
from gruffpy.version import VERSION


def run_analysis(request: AnalysisRunRequest) -> AnalysisReport:
    """Run the end-to-end analysis pipeline and return a single ``AnalysisReport``.

    Args:
        request: Validated analysis options from the CLI, dashboard, or another caller.

    Returns:
        Fully-populated report ready to be handed to a reporter.
    """
    baseline_options = request.baseline if request.baseline is not None else BaselineOptions()
    registry = RuleRegistry.defaults()
    config, config_loaded_from, diagnostics = _load_analysis_config(
        project_root=request.project_root,
        config_path=request.config_path,
        no_config=request.no_config,
        registry=registry,
    )
    fail_threshold = request.fail_threshold
    if request.config_severity_command:
        configured = config.minimum_severity.get(request.config_severity_command)
        if configured is not None:
            fail_threshold = configured

    (
        discovery_result,
        units,
        files_parsed,
        parse_diagnostics,
        changed,
    ) = _discover_and_parse_sources(
        project_root=request.project_root,
        paths=request.paths,
        include_ignored=request.include_ignored,
        config=config,
        changed_ranges=request.changed_ranges,
        since=request.since,
        diff_mode=request.diff_mode,
        diff_patch=request.diff_patch,
        diagnostics=diagnostics,
    )
    diagnostics.extend(_missing_path_diagnostics(discovery_result.missing_paths))
    diagnostics.extend(parse_diagnostics)

    context = RuleContext(project_root=str(request.project_root), config=config)
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
        project_root=request.project_root,
        findings=findings,
        diagnostics=diagnostics,
        options=baseline_options,
        scan_scope=_scan_scope(request.paths),
    )
    changed_filter_result = filter_findings_for_changed_regions(
        findings,
        units,
        changed,
        request.changed_scope,
    )
    findings = changed_filter_result.findings
    score = ScoreCalculator().calculate(findings, diff_active=changed.active)

    exit_code = compute_exit_code(findings, diagnostics, fail_threshold)
    display_findings = request.display_filter.filter_findings(findings)

    return AnalysisReport(
        tool_version=VERSION,
        requested_paths=tuple(request.paths) if request.paths else (".",),
        format=request.output.value,
        fail_on=fail_threshold.value,
        files_discovered=len(discovery_result.files),
        files_parsed=files_parsed,
        ignored_paths=discovery_result.ignored_paths,
        ignored_path_details=discovery_result.ignored_path_reasons,
        missing_paths=discovery_result.missing_paths,
        diagnostics=tuple(diagnostics),
        findings=tuple(display_findings),
        exit_code=exit_code,
        config_path=config_loaded_from,
        score=score,
        filters=request.display_filter,
        extensions=ReportExtensions(
            baseline=baseline_report,
            diff=_changed_region_payload(changed, changed_filter_result.suppressed_count),
        ),
        output_volume_hint_threshold=config.output_volume_hint_threshold,
        suppressed_count=changed_filter_result.suppressed_count if changed.active else None,
    )


def _discover_and_parse_sources(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    include_ignored: bool,
    config: AnalysisConfig,
    changed_ranges: str,
    since: str,
    diff_mode: str,
    diff_patch: str,
    diagnostics: list[RunDiagnostic],
) -> tuple[
    SourceDiscoveryResult,
    list[AnalysisUnit],
    int,
    list[RunDiagnostic],
    ChangedRegionSet,
]:
    discovery = SourceDiscovery(project_root)
    discovery_result = discovery.discover(
        list(paths),
        include_ignored=include_ignored,
        configured_ignore_patterns=config.ignored_path_patterns,
    )
    changed = _resolve_changed_regions(
        project_root=project_root,
        paths=paths,
        source_paths=tuple(file.display_path for file in discovery_result.files),
        changed_ranges=changed_ranges,
        since=since,
        diff_mode=diff_mode,
        diff_patch=diff_patch,
        diagnostics=diagnostics,
    )
    if changed.active and not changed_ranges:
        discovery_result = replace(
            discovery_result,
            files=filter_sources_for_changed_regions(discovery_result.files, changed),
        )
    units, files_parsed, parse_diagnostics = _parse_sources(discovery_result.files)
    return discovery_result, units, files_parsed, parse_diagnostics, changed


def _resolve_changed_regions(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    source_paths: tuple[str, ...],
    changed_ranges: str,
    since: str,
    diff_mode: str,
    diff_patch: str,
    diagnostics: list[RunDiagnostic],
) -> ChangedRegionSet:
    try:
        if changed_ranges:
            return parse_explicit_ranges(source_paths, changed_ranges)
        if diff_mode == "-":
            return parse_unified_diff("stdin", diff_patch)
        if diff_patch:
            return parse_unified_diff("stdin", diff_patch)
        if since:
            return changed_regions_from_git(project_root, since, paths)
        if diff_mode:
            return changed_regions_from_git(project_root, diff_mode, paths)
    except ValueError as exc:
        diagnostics.append(RunDiagnostic(type="diff-error", message=str(exc)))
        return ChangedRegionSet(source="")
    return ChangedRegionSet(source="")


def _changed_region_payload(
    changed: ChangedRegionSet,
    suppressed_count: int,
) -> dict[str, object] | None:
    if not changed.active:
        return None
    return {
        "enabled": True,
        "source": changed.source,
        "changedFiles": list(changed.changed_files),
        "suppressedCount": suppressed_count,
        "caveat": "diff mode is changed-region scoped and project-wide rules may need full context",
    }


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
    scan_scope: str,
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
        scan_scope=scan_scope,
    )


def _scan_scope(paths: tuple[str, ...]) -> str:
    if not paths or any(p == "." for p in paths):
        return "full-project"
    return "partial-scope"


def _baseline_option_conflict(options: BaselineOptions) -> RunDiagnostic | None:
    if options.generate_path is not None and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message=(
                "--baseline-path and --generate-baseline/--generate-baseline-path "
                "are mutually exclusive."
            ),
        )
    if options.disabled and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message="--no-baseline cannot be combined with --baseline-path.",
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
    scan_scope: str,
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
            scan_scope=scan_scope,
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
    loaded_config, source = loader.load(config_path)

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
