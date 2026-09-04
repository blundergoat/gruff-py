"""Run the analysis pipeline shared by ``gruff-py analyse`` and dashboard scans.

The pipeline turns a user's paths and options into deterministic findings, diagnostics, scores,
and exit status. Reporters receive one complete result without reapplying config or suppression.
"""

from dataclasses import dataclass, replace
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
from gruffpy.analysis.report import AnalysisReport, MachineReportContext, ReportExtensions
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.suppression_summary import SuppressionSummary
from gruffpy.config.analysis_config import AnalysisConfig, DeepScanBudget
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.rule.context import RuleContext
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.suppression.filter import apply_suppressions
from gruffpy.suppression.parser import ParsedSuppressions, parse_suppressions
from gruffpy.suppression.sensitive_exclusion_filter import partition_sensitive_exclusions
from gruffpy.version import VERSION

_PARTIAL_PROJECT_CONTEXT_CAVEAT = "partial project scan: project-wide rules may need full-project context"


@dataclass(frozen=True, slots=True)
class _ReportAssembly:
    """Hold the completed scan state used to build one user-facing report.

    This keeps report rendering separate from discovery, analysis, and filtering.
    CLI and dashboard consumers receive the same assembled view.
    """

    request: AnalysisRunRequest
    config: AnalysisConfig
    config_loaded_from: str | None
    fail_threshold: FailThreshold
    discovery_result: SourceDiscoveryResult
    files_parsed: int
    diagnostics: list[RunDiagnostic]
    summary_findings: list[Finding]
    display_findings: list[Finding]
    exit_code: int
    score: ScoreReport
    hidden_by_display_filter: int
    partial_context_caveat: str | None
    baseline_report: BaselineReport | None
    changed: ChangedRegionSet
    changed_suppressed_count: int
    config_warnings: tuple[str, ...]
    suppressions: tuple[SuppressionSummary, ...]


def _evaluated_file_count(units: list[AnalysisUnit]) -> int:
    """Count the Python files this run evaluated - the ratified scoring denominator.

    Deliberately narrower than ``files_parsed``, which also counts the text inputs the raw-text
    rules read: a README is scanned but carries no Python to score, so including it would divide
    real findings by files no Python rule ever evaluated.

    Args:
        units: Parsed analysis units for the run, including any that failed to parse.

    Returns:
        Python files that parsed successfully; zero means nothing was evaluated.
    """
    return sum(1 for unit in units if not unit.has_parse_errors() and unit.file.is_python())


def run_analysis(request: AnalysisRunRequest) -> AnalysisReport:
    """Run the end-to-end analysis pipeline and return a single ``AnalysisReport``.

    Args:
        request: Validated analysis options from the CLI, dashboard, or another caller.

    Returns:
        Fully-populated report ready to be handed to a reporter.
    """
    registry = RuleRegistry.defaults()
    config, config_loaded_from, diagnostics, config_warnings = _load_analysis_config(
        project_root=request.project_root,
        config_path=request.config_path,
        no_config=request.no_config,
        registry=registry,
        strict_config=request.strict_config,
    )
    config, fail_threshold = _resolve_threshold_and_exclusions(request, config)
    config = _apply_deep_scan_budget_override(config, request.deep_scan_budget)

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

    scan_scope = _resolve_scan_scope(request, changed)
    context = RuleContext(
        project_root=str(request.project_root),
        config=config,
        scan_scope=scan_scope,
    )
    suppressions_by_file = _parse_suppressions(units, registry)
    diagnostics.extend(_suppression_diagnostics(suppressions_by_file))
    findings = _collect_findings(
        registry=registry,
        units=units,
        context=context,
        suppressions_by_file=suppressions_by_file,
    )
    # Reviewed sensitive-data exclusions drop out before baselining, scoring, and the exit code,
    # exactly like the inline directive channel, and every drop is counted for the report.
    findings, suppressions = partition_sensitive_exclusions(findings, config.sensitive_exclusions)
    baseline_report = _handle_baseline(
        project_root=request.project_root,
        findings=findings,
        diagnostics=diagnostics,
        options=request.baseline if request.baseline is not None else BaselineOptions(),
        scan_scope=scan_scope,
    )
    changed_filter_result = filter_findings_for_changed_regions(
        findings,
        units,
        changed,
        request.changed_scope,
    )
    findings = changed_filter_result.findings
    score = ScoreCalculator().calculate(findings, _evaluated_file_count(units), diff_active=changed.active)

    exit_code = compute_exit_code(findings, diagnostics, fail_threshold)
    display_findings = request.display_filter.filter_findings(findings)
    hidden_by_display_filter = len(findings) - len(display_findings)
    partial_context_caveat = _partial_project_context_caveat(registry, config, scan_scope)

    return _build_report(
        _ReportAssembly(
            request=request,
            config=config,
            config_loaded_from=config_loaded_from,
            fail_threshold=fail_threshold,
            discovery_result=discovery_result,
            files_parsed=files_parsed,
            diagnostics=diagnostics,
            summary_findings=findings,
            display_findings=display_findings,
            exit_code=exit_code,
            score=score,
            hidden_by_display_filter=hidden_by_display_filter,
            partial_context_caveat=partial_context_caveat,
            baseline_report=baseline_report,
            changed=changed,
            changed_suppressed_count=changed_filter_result.suppressed_count,
            config_warnings=config_warnings,
            suppressions=suppressions,
        )
    )


def _build_report(assembly: _ReportAssembly) -> AnalysisReport:
    """Project completed scan state into the report consumed by CLI and dashboard users."""
    return AnalysisReport(
        tool_version=VERSION,
        requested_paths=tuple(assembly.request.paths) if assembly.request.paths else (".",),
        format=assembly.request.output.value,
        fail_on=assembly.fail_threshold.value,
        files_discovered=len(assembly.discovery_result.files),
        files_parsed=assembly.files_parsed,
        ignored_paths=assembly.discovery_result.ignored_paths,
        ignored_path_details=assembly.discovery_result.ignored_path_reasons,
        missing_paths=assembly.discovery_result.missing_paths,
        diagnostics=tuple(assembly.diagnostics),
        findings=tuple(assembly.display_findings),
        exit_code=assembly.exit_code,
        config_path=assembly.config_loaded_from,
        score=assembly.score,
        filters=assembly.request.display_filter,
        hidden_by_display_filter=assembly.hidden_by_display_filter,
        partial_context_caveat=assembly.partial_context_caveat,
        extensions=ReportExtensions(
            baseline=assembly.baseline_report,
            diff=_changed_region_payload(assembly.changed, assembly.changed_suppressed_count),
        ),
        output_volume_hint_threshold=assembly.config.output_volume_hint_threshold,
        suppressed_count=(assembly.changed_suppressed_count if assembly.changed.active else None),
        config_warnings=assembly.config_warnings,
        suppressions=assembly.suppressions,
        machine_context=MachineReportContext(
            project_root=str(assembly.request.project_root),
            include_ignored=assembly.request.include_ignored,
            summary_findings=tuple(assembly.summary_findings),
        ),
    )


def _resolve_threshold_and_exclusions(
    request: AnalysisRunRequest,
    config: AnalysisConfig,
) -> tuple[AnalysisConfig, FailThreshold]:
    """Apply the configured per-command fail threshold and execution rule exclusions.

    Args:
        request: The active run request.
        config: Config resolved from defaults and the user's config file.

    Returns:
        The config (with any execution-level rule exclusions merged) and the
        effective fail threshold.
    """
    fail_threshold = request.fail_threshold
    if request.config_severity_command:
        configured = config.minimum_severity.get(request.config_severity_command)
        if configured is not None:
            fail_threshold = configured
    if request.execution_exclude_rules:
        config = _with_execution_exclude_rules(config, request.execution_exclude_rules)
    return config, fail_threshold


def _partial_project_context_caveat(
    registry: RuleRegistry,
    config: AnalysisConfig,
    scan_scope: str,
) -> str | None:
    """Return the caveat users need when project-wide rules receive only part of a project."""
    if scan_scope == "full-project":
        return None
    if any(isinstance(rule, ProjectRuleProtocol) for rule in registry.enabled_rules(config)):
        return _PARTIAL_PROJECT_CONTEXT_CAVEAT
    return None


def _with_execution_exclude_rules(
    config: AnalysisConfig,
    exclude_rules: tuple[str, ...],
) -> AnalysisConfig:
    """Merge command-only rule exclusions into the config used for this user request."""
    selection = config.rule_selection
    merged = tuple(dict.fromkeys((*selection.exclude_rules, *exclude_rules)))
    return config.with_rule_selection(replace(selection, exclude_rules=merged))


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
    """Discover requested files, narrow diff scans, and parse sources for rule execution."""
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
    units, files_parsed, parse_diagnostics = _parse_sources(
        discovery_result.files,
        config.deep_scan_budget,
    )
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
    """Resolve the user's explicit ranges, patch, or Git selector into changed source regions."""
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
    # For example, a malformed ``--changed-ranges`` value becomes a CLI diagnostic rather than
    # a traceback.
    except ValueError as exc:
        diagnostics.append(RunDiagnostic(type="diff-error", message=str(exc)))
        return ChangedRegionSet(source="")
    return ChangedRegionSet(source="")


def _changed_region_payload(
    changed: ChangedRegionSet,
    suppressed_count: int,
) -> dict[str, object] | None:
    """Describe active changed-region filtering in the JSON extension shown to users."""
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
    suppressions_by_file: dict[str, ParsedSuppressions],
) -> list[Finding]:
    """Run enabled rules and inline suppressions, then order the findings shown to the user."""
    findings = registry.analyse(units, context)
    findings = apply_suppressions(findings, suppressions_by_file)
    # Findings without a source line sort at the file start so repeated CLI runs remain stable.
    findings.sort(key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message))
    return findings


def _handle_baseline(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    options: BaselineOptions,
    scan_scope: str,
) -> BaselineReport | None:
    """Apply the user's baseline choice and append actionable diagnostics when it cannot run."""
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


def _resolve_scan_scope(request: AnalysisRunRequest, changed: ChangedRegionSet) -> str:
    """Classify the run as full-project or partial for caveats and baseline staleness.

    ``--diff`` and ``--since`` make the run partial before rules execute; explicit
    ``--changed-ranges`` filters later, so the user's requested paths decide.
    """
    if changed.active and not request.changed_ranges:
        return "partial-scope"
    return _scan_scope(request.paths, request.project_root)


def _scan_scope(paths: tuple[str, ...], project_root: Path) -> str:
    """Classify the requested paths as a full-project or partial scan.

    Paths such as ``.``, ``./``, ``src/..``, and the absolute project root all give
    users the same full-project behavior.
    """
    if not paths:
        return "full-project"
    root = project_root.resolve()
    if any((root / path).resolve() == root for path in paths):
        return "full-project"
    return "partial-scope"


def _baseline_option_conflict(options: BaselineOptions) -> RunDiagnostic | None:
    """Explain mutually exclusive baseline flags before users receive a misleading scan."""
    if options.generate_path is not None and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message=("--baseline-path and --generate-baseline/--generate-baseline-path are mutually exclusive."),
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
    """Generate a requested baseline, converting file failures into user-facing diagnostics."""
    try:
        return generate_baseline(project_root=project_root, path=path, findings=findings)
    # For example, an unwritable baseline path should explain the filesystem failure without
    # a traceback.
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
    """Apply an available baseline while keeping malformed or unreadable files visible to users."""
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
    # For example, invalid baseline JSON becomes a diagnostic and leaves current findings intact.
    except BaselineError as exc:
        diagnostics.append(RunDiagnostic(type="baseline-error", message=str(exc), path=str(selected_path)))
        return None
    findings[:] = result.findings
    return result.report


def _resolve_baseline_selection(project_root: Path, explicit_path: Path | None) -> tuple[Path | None, str]:
    """Choose the explicit or default baseline path a user asked the scan to apply."""
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
    strict_config: bool = False,
) -> tuple[AnalysisConfig, str | None, list[RunDiagnostic], tuple[str, ...]]:
    """Load settings for this request and preserve the config source and warnings for users."""
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
            (),
        )
    if no_config:
        return config, None, [], ()

    loader = ConfigLoader(project_root, config, strict=strict_config)
    loaded_config, source = loader.load(config_path)

    return loaded_config, str(source) if source is not None else None, [], loader.warnings


def _parse_sources(
    source_files: tuple[SourceFile, ...],
    deep_scan_budget: DeepScanBudget,
) -> tuple[list[AnalysisUnit], int, list[RunDiagnostic]]:
    """Parse discovered files and retain parse failures for the final CLI report."""
    parser = PythonFileParser()
    units: list[AnalysisUnit] = []
    diagnostics: list[RunDiagnostic] = []
    files_parsed = 0

    for source_file in source_files:
        unit = parser.parse(source_file, deep_scan_budget)
        units.append(unit)
        if not unit.has_parse_errors():
            files_parsed += 1
        diagnostics.extend(
            RunDiagnostic(
                type=diagnostic.type,
                message=diagnostic.message,
                file_path=source_file.display_path,
                line=diagnostic.line,
                invalidates_run=False if diagnostic.non_fatal else None,
            )
            for diagnostic in unit.diagnostics
        )

    return units, files_parsed, diagnostics


def _missing_path_diagnostics(missing_paths: tuple[str, ...]) -> list[RunDiagnostic]:
    """Turn requested paths that do not exist into diagnostics users can act on."""
    return [RunDiagnostic(type="missing-path", message="path not found", path=missing) for missing in missing_paths]


def _parse_suppressions(
    units: list[AnalysisUnit],
    registry: RuleRegistry,
) -> dict[str, ParsedSuppressions]:
    """Parse inline suppression directives before findings are prepared for the user."""
    known_rule_ids = frozenset(rule.definition().id for rule in registry.all())
    return {
        unit.file.display_path: parse_suppressions(
            unit.source,
            known_rule_ids=known_rule_ids,
        )
        for unit in units
        if unit.source and not unit.is_deep_scan_bounded()
    }


def _suppression_diagnostics(
    suppressions_by_file: dict[str, ParsedSuppressions],
) -> list[RunDiagnostic]:
    """Expose malformed or unknown suppression directives alongside scan findings."""
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
    if any(diagnostic.invalidates_run is not False for diagnostic in diagnostics):
        return 2
    for finding in findings:
        if fail_threshold.is_triggered_by(finding.severity):
            return 1
    return 0


def _apply_deep_scan_budget_override(
    config: AnalysisConfig,
    value: str,
) -> AnalysisConfig:
    """Apply the atomic CLI budget after config so both limits share provenance."""
    if value == "":
        return config
    current = config.deep_scan_budget
    if value == "off":
        return config.with_deep_scan_budget(
            DeepScanBudget(
                enabled=False,
                max_lines=current.max_lines,
                max_bytes=current.max_bytes,
                override="cli",
            )
        )
    parts = value.split(":")
    if len(parts) != 2:
        raise ConfigError("--deep-scan-budget must be two positive integers as LINES:BYTES, or off.")
    try:
        max_lines, max_bytes = (int(part) for part in parts)
    except ValueError as exc:
        raise ConfigError("--deep-scan-budget must be two positive integers as LINES:BYTES, or off.") from exc
    if max_lines <= 0 or max_bytes <= 0:
        raise ConfigError("--deep-scan-budget must be two positive integers as LINES:BYTES, or off.")
    return config.with_deep_scan_budget(
        DeepScanBudget(
            enabled=True,
            max_lines=max_lines,
            max_bytes=max_bytes,
            override="cli",
        )
    )
