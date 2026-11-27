"""Run the analysis pipeline shared by ``gruff-py analyse`` and dashboard scans.

The pipeline turns a user's paths and options into deterministic findings, diagnostics, scores,
and exit status. Reporters receive one complete result without reapplying config or suppression.
"""

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import (
    BaselineCollision,
    BaselineError,
    BaselineOptions,
    BaselineReport,
    apply_baseline,
    default_baseline_path,
    generate_baseline,
    is_unreviewed_baseline_status,
    migrate_baseline,
    require_overwritable_default_path,
)
from gruffpy.analysis.changed_region import (
    CHANGED_REGION_DIAGNOSTIC_TYPE,
    ChangedRegionSet,
    changed_regions_from_git,
    filter_findings_for_changed_regions,
    filter_sources_for_changed_regions,
    is_finding_location_changed,
    parse_explicit_ranges,
    parse_unified_diff,
)
from gruffpy.analysis.report import AnalysisReport, MachineReportContext, ReportExtensions
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.suppression_summary import SuppressedFinding, SuppressionSummary
from gruffpy.config.analysis_config import AnalysisConfig, DeepScanBudget
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.config.rule_selection import RuleSelection
from gruffpy.finding.baseline_identity import declaration_position_from_spans, declaration_spans, finding_identities
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.parser.python_parser import PythonFileParser
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.exported_but_unreferenced_rule import ExportedButUnreferencedRule
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.score_calculator import ScoreCalculator
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.source.discovery import SourceDiscovery, SourceDiscoveryResult
from gruffpy.source.source_file import SourceFile
from gruffpy.suppression.filter import apply_suppressions
from gruffpy.suppression.inline_suppression_filter import apply_inline_suppressions
from gruffpy.suppression.parser import ParsedSuppressions, parse_suppressions
from gruffpy.suppression.sensitive_exclusion_filter import (
    apply_built_in_test_path_skip,
    partition_sensitive_exclusions,
)
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
    display_filter: FindingDisplayFilter
    hidden_by_display_filter: int
    partial_context_caveat: str | None
    baseline_report: BaselineReport | None
    changed: ChangedRegionSet
    changed_suppressed_count: int
    config_warnings: tuple[str, ...]
    suppressions: tuple[SuppressionSummary, ...]
    suppressed_findings: tuple[SuppressedFinding, ...]


def _evaluated_file_count(units: list[AnalysisUnit]) -> int:
    """Count successfully parsed Python files for the scoring denominator.

    Text inputs contribute to files_parsed but carry no Python to score.

    Args:
        units: Parsed analysis units for the run, including any that failed to parse.

    Returns:
        Number of Python files without fatal parser diagnostics. Zero means there are no Python files in the scoring denominator.
    """
    return sum(1 for unit in units if not unit.has_parse_errors() and unit.file.is_python())


def run_analysis(request: AnalysisRunRequest) -> AnalysisReport:
    """Run the requested scan and return one result for the terminal, dashboard or hook.
    The runner applies path selection, rule settings and baseline choices before it scores findings or decides the exit code.

    Args:
        request: Selects the project and inputs, rule settings, baseline operation and report filters.

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
    config, fail_threshold = _resolve_threshold_and_exclusions(request, config, registry)
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
    diagnostics.extend(
        RunDiagnostic(type="target-error", message=f"Input path resolves outside the project root: {path}", path=path)
        for path in discovery_result.outside_paths
    )
    diagnostics.extend(parse_diagnostics)

    # A broken input, such as a symlink loop, leaves the scan without complete project context.
    scan_scope = "partial-scope" if discovery_result.has_input_errors() else _resolve_scan_scope(request, changed)
    # A syntax error or a budget limit can leave Python source out of cross-file checks.
    if any(unit.file.is_python() and unit.tree is None for unit in units):
        scan_scope = "partial-scope"
    reference_trees = _reference_only_trees(request, config, registry, scan_scope, discovery_result)
    # If even one ignored Python file could not be parsed, unused-export checks lack a complete reference graph.
    if reference_trees is None:
        scan_scope = "partial-scope"
    findings, suppressions, suppressed_findings = _collect_unsuppressed_findings(
        registry=registry,
        units=units,
        config=config,
        project_root=request.project_root,
        scan_scope=scan_scope,
        diagnostics=diagnostics,
        reference_trees=reference_trees or (),
    )
    baseline_report, baseline_statuses = _handle_baseline(
        project_root=request.project_root,
        findings=findings,
        diagnostics=diagnostics,
        options=request.baseline if request.baseline is not None else BaselineOptions(),
        scan_scope=scan_scope,
        units=units,
        changed=changed,
    )
    changed_filter_result = filter_findings_for_changed_regions(
        findings,
        units,
        changed,
        request.changed_scope,
    )
    findings = changed_filter_result.findings
    suppressed_findings = _filter_suppressed_findings_for_changed_regions(
        suppressed_findings,
        units,
        changed,
        request.changed_scope,
    )
    # If the requested scope fails to resolve, omit findings and suppressed results so the report cannot be mistaken for a scoped scan.
    if any(diagnostic.type == CHANGED_REGION_DIAGNOSTIC_TYPE for diagnostic in diagnostics):
        findings = []
        suppressed_findings = ()
    score = ScoreCalculator().calculate(findings, _evaluated_file_count(units), diff_active=changed.active)

    exit_code = compute_exit_code(
        findings,
        diagnostics,
        fail_threshold,
        min_confidence=request.min_confidence,
        new_statuses=baseline_statuses if request.fail_on_new else None,
    )
    display_filter = request.display_filter.with_configured_floor(config.display_floor)
    display_findings = display_filter.filter_findings(findings)
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
            display_filter=display_filter,
            hidden_by_display_filter=hidden_by_display_filter,
            partial_context_caveat=partial_context_caveat,
            baseline_report=baseline_report,
            changed=changed,
            changed_suppressed_count=changed_filter_result.suppressed_count,
            config_warnings=config_warnings,
            suppressions=suppressions,
            suppressed_findings=suppressed_findings,
        )
    )


def _collect_unsuppressed_findings(
    *,
    registry: RuleRegistry,
    units: list[AnalysisUnit],
    config: AnalysisConfig,
    project_root: Path,
    scan_scope: str,
    diagnostics: list[RunDiagnostic],
    reference_trees: tuple[ast.Module, ...] = (),
) -> tuple[list[Finding], tuple[SuppressionSummary, ...], tuple[SuppressedFinding, ...]]:
    """Collect the findings that reach baseline matching after suppression policies.
    Audit rows explain what was removed, and the remaining findings carry the identities the baseline will use.

    Args:
        registry: Rule registry whose enabled rules run.
        units: Parsed source units in scan order.
        config: Effective analysis configuration, including sensitive-data exclusions.
        project_root: Project root the rule context reports paths against.
        scan_scope: Resolved scope label the rule context carries.
        diagnostics: Run diagnostics; inline-suppression diagnostics are appended in place.
        reference_trees: Modules the configured ignore globs keep out of the report, which project rules may
            read references from; empty means none apply.

    Returns:
        Tuple (findings, suppressions, removed): findings surviving native directives, sensitive-data exclusions,
        test-path skipping, other tools' comments and repeated-claim merging, with available baseline identities;
        accumulated audit rows; and findings removed by those comments or claim merging, with their reasons.
    """
    context = RuleContext(
        project_root=str(project_root),
        config=config,
        scan_scope=scan_scope,
        reference_trees=reference_trees,
    )
    suppressions_by_file = _parse_suppressions(units, registry)
    diagnostics.extend(_suppression_diagnostics(suppressions_by_file))
    findings = _collect_findings(
        registry=registry,
        units=units,
        context=context,
        suppressions_by_file=suppressions_by_file,
    )
    # Configured sensitive-data exclusions remove findings before baselining and gating and keep their counts in the report.
    findings, suppressions = partition_sensitive_exclusions(findings, config.sensitive_exclusions)
    # A configured entry claims its findings first, so its count stays what the user wrote it for.
    findings, suppressions = apply_built_in_test_path_skip(findings, suppressions)
    # Assign available baseline identities before filtering so SARIF and baseline matching can reuse the same occurrence ordinals.
    findings = _with_baseline_identities(findings, units)
    # Preserve assigned identities on findings removed by another tool's comment or claim merging so SARIF can still report them.
    sources = {unit.file.display_path: unit.source for unit in units if not unit.is_deep_scan_bounded()}
    return apply_inline_suppressions(findings, suppressions, sources)


def _build_report(assembly: _ReportAssembly) -> AnalysisReport:
    """Project completed scan state into the report consumed by CLI and dashboard users.

    Args:
        assembly: Completed scan state for one run; its display findings become the report findings, while its summary findings travel in the machine
            context.

    Returns:
        Report ready for a reporter, with requested paths defaulting to the project root when none were given and the diff extension and suppressed
        count present only when changed-region filtering is active.
    """
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
        # The effective filter, so a configured minimumSeverity floor is reported exactly as the flag is.
        filters=assembly.display_filter,
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
        suppressed_findings=assembly.suppressed_findings,
        machine_context=MachineReportContext(
            project_root=str(assembly.request.project_root),
            include_ignored=assembly.request.include_ignored,
            summary_findings=tuple(assembly.summary_findings),
        ),
    )


def _resolve_threshold_and_exclusions(
    request: AnalysisRunRequest,
    config: AnalysisConfig,
    registry: RuleRegistry,
) -> tuple[AnalysisConfig, FailThreshold]:
    """Resolve the effective rule set and exit threshold for this command.
    For example, `analyse` can use its configured gate when the user leaves `--fail-on` unset.

    Args:
        request: Supplies the requested fail threshold, command-specific config key and execution rule selectors.
        config: Config resolved from defaults and the user's config file.
        registry: Supplies rule definitions for matching CLI selectors.

    Returns:
        The config with execution selectors merged and the command's configured fail threshold, falling back to the request threshold.
    """
    fail_threshold = request.fail_threshold
    # An explicit CLI threshold leaves the config lookup disabled for this invocation.
    if request.config_severity_command:
        configured_threshold = config.minimum_severity.get(request.config_severity_command)
        # A command with no saved gate keeps the threshold that came with the request.
        if configured_threshold is not None:
            fail_threshold = configured_threshold
    _require_known_display_rules(config, request.display_filter)
    config = _with_execution_selectors(config, request, registry)
    return config, fail_threshold


def _partial_project_context_caveat(
    registry: RuleRegistry,
    config: AnalysisConfig,
    scan_scope: str,
) -> str | None:
    """Return the caveat users need when project-wide rules receive only part of a project.

    Args:
        registry: Rule registry whose enabled rules are checked for project-wide rules.
        config: Effective analysis configuration that decides which rules are enabled.
        scan_scope: Resolved scope label; a full-project scan never needs the caveat.

    Returns:
        The partial project scan caveat text when the scan is partial and at least one enabled rule is project-wide; None otherwise.
    """
    if scan_scope == "full-project":
        return None
    if any(isinstance(rule, ProjectRuleProtocol) for rule in registry.enabled_rules(config)):
        return _PARTIAL_PROJECT_CONTEXT_CAVEAT
    return None


def _with_execution_selectors(config: AnalysisConfig, request: AnalysisRunRequest, registry: RuleRegistry) -> AnalysisConfig:
    """Narrow rule execution to the user's explicit rule and pillar selections.
    Unlike a display filter, this changes which findings count toward the score, the exit gate and any baseline written by the scan.

    Args:
        config: Effective configuration from defaults and any project file.
        request: The user's run request, carrying any selectors they typed.
        registry: Supplies definitions to resolve the invocation's rule and pillar filters.

    Returns:
        Config whose rules must pass both the project and invocation filters.

    Raises:
        ConfigError: When the invocation names an unknown rule.
    """
    selection = config.rule_selection
    unknown_rule_ids = sorted(set(request.execution_include_rules + request.execution_exclude_rules) - config.rules.keys())
    # A misspelling must fail visibly instead of letting a scan pass with the wrong checks.
    if unknown_rule_ids:
        raise ConfigError(f"Unknown execution rule IDs: {', '.join(unknown_rule_ids)}.")
    requested_exclusions = (*selection.exclude_rules, *request.execution_exclude_rules)
    excluded_pillars = tuple(dict.fromkeys((*selection.exclude_pillars, *request.execution_exclude_pillars)))
    # An explicit include list narrows the configured checks. It cannot bring back a disabled rule.
    if request.execution_include_rules or request.execution_include_pillars:
        invocation_selection = RuleSelection(rules=request.execution_include_rules, pillars=request.execution_include_pillars)
        requested_exclusions += tuple(
            definition.id for rule in registry.all() if not invocation_selection.is_allowed(definition := rule.definition())
        )
    excluded_rules = tuple(dict.fromkeys(requested_exclusions))
    # With no effective rule change, the existing project settings remain the source of truth for this run.
    if excluded_rules == selection.exclude_rules and excluded_pillars == selection.exclude_pillars:
        return config
    return config.with_rule_selection(replace(selection, exclude_rules=excluded_rules, exclude_pillars=excluded_pillars))


def _require_known_display_rules(config: AnalysisConfig, display_filter: FindingDisplayFilter) -> None:
    """Refuse a display filter that names a rule this port does not register.

    Args:
        config: Effective configuration whose rule table holds every registered rule ID.
        display_filter: The invocation's display filter, carrying the --show-rule and --hide-rule values.

    Returns:
        None. Returns normally when every rule the filter names is registered.

    Raises:
        ConfigError: When --show-rule or --hide-rule names an unknown or retired rule.
    """
    unknown_rule_ids = sorted(set(display_filter.include_rules + display_filter.exclude_rules) - config.rules.keys())
    # A misspelt --show-rule hides every finding and a misspelt --hide-rule hides none, while the score and exit code still count them all.
    if unknown_rule_ids:
        raise ConfigError(f"Unknown display rule IDs: {', '.join(unknown_rule_ids)}.")


def _discover_and_parse_sources(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    include_ignored: bool,
    config: AnalysisConfig,
    changed_ranges: str | None,
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
    """Discover requested files, narrow diff scans, and parse sources for rule execution.

    Args:
        project_root: Project root that discovery and Git diff resolution run against.
        paths: Requested scan targets that also limit a Git diff. An empty tuple starts discovery at the project root.
        include_ignored: When true, discovery also returns gitignored and default-excluded paths; configured ignore globs and VCS directories still
            apply.
        config: Effective configuration supplying the configured ignore globs and the deep-scan budget the parser applies.
        changed_ranges: Explicit line ranges used to filter findings after parsing. None leaves scope selection to the patch or Git options.
            An empty or invalid value adds a diagnostic and leaves the discovered files unfiltered.
        since: Git ref from the since option; empty when not given.
        diff_mode: Diff option value: a dash means diff_patch holds the patch read from standard input, any other non-empty value is a Git selector,
            and empty means no diff mode.
        diff_patch: Unified diff text. Without explicit ranges, a dash parses it as stdin and non-empty text takes precedence over Git selectors.
            Empty text with a dash selects no files. In other modes, empty text leaves scope selection to the other options.
        diagnostics: Run diagnostics; a changed-region resolution failure is appended in place.

    Returns:
        The tuple contains the discovery result, one unit per selected file, the count of units without fatal parser diagnostics, parser diagnostics
        for the caller to append, and the changed-region set. An active patch or Git scope narrows discovery to changed files. All discovered files
        are retained when no scope is active, including after a resolution failure.
    """
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
    if changed.active and changed_ranges is None:
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
    changed_ranges: str | None,
    since: str,
    diff_mode: str,
    diff_patch: str,
    diagnostics: list[RunDiagnostic],
) -> ChangedRegionSet:
    """Resolve the user's explicit ranges, patch, or Git selector into changed source regions.

    Args:
        project_root: Project root that the since ref and Git diff selectors are resolved in, passed to git -C.
        paths: Requested paths that limit a Git diff.
        source_paths: Display paths of the discovered files; explicit ranges apply to each of them.
        changed_ranges: Explicit changed-ranges value; None when not given, while a given but empty value is refused by the parser and becomes a
            diagnostic.
        since: Git ref from the since option; empty when not given.
        diff_mode: Diff option value: a dash parses diff_patch as standard input, any other non-empty value is a Git selector, and empty means no diff
            mode.
        diff_patch: Unified diff text read for the run; parsed as the patch whenever it is non-empty and no explicit ranges were given, even without a
            dash.
        diagnostics: Run diagnostics; a ValueError from parsing or Git resolution is appended in place as a changed-region diagnostic.

    Returns:
        Changed-region set from the first option that applies, checked in the order explicit ranges, a dash diff mode, non-empty patch text, the since
        ref, then a diff selector; an empty, inactive set when no option was given or resolution failed.
    """
    try:
        # A given-but-empty value reaches the parser, which refuses it: the caller scoped the run to nothing.
        if changed_ranges is not None:
            return parse_explicit_ranges(source_paths, changed_ranges)
        if diff_mode == "-":
            return parse_unified_diff("stdin", diff_patch)
        if diff_patch:
            return parse_unified_diff("stdin", diff_patch)
        if since:
            return changed_regions_from_git(project_root, since, paths)
        if diff_mode:
            return changed_regions_from_git(project_root, diff_mode, paths)
    # For example, a malformed --changed-ranges value becomes a CLI diagnostic rather than a traceback.
    except ValueError as exc:
        diagnostics.append(RunDiagnostic(type=CHANGED_REGION_DIAGNOSTIC_TYPE, message=str(exc)))
        return ChangedRegionSet(source="")
    return ChangedRegionSet(source="")


def _changed_region_payload(
    changed: ChangedRegionSet,
    suppressed_count: int,
) -> dict[str, object] | None:
    """Describe active changed-region filtering in the JSON extension shown to users.

    Args:
        changed: Resolved changed-region set; only an active set produces a payload.
        suppressed_count: Number of findings changed-region filtering removed, reported as suppressedCount.

    Returns:
        Diff extension mapping with enabled, source, changedFiles, suppressedCount and a caveat about project-wide rules; None when changed-region
        filtering is inactive.
    """
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
    """Run enabled rules and inline suppressions, then order the findings shown to the user.

    Args:
        registry: Rule registry that analyses the units.
        units: Parsed source units in scan order.
        context: Rule context carrying the project root, config, scan scope and reference trees.
        suppressions_by_file: Parsed suppression directives keyed by display path; a file absent from it has no directives applied.

    Returns:
        Findings that survive the directives, sorted by file path, line (a finding without a line sorts as line 0), rule id and message.
    """
    findings = registry.analyse(units, context)
    findings = apply_suppressions(findings, suppressions_by_file)
    # Findings without a source line sort at the file start so repeated CLI runs remain stable.
    findings.sort(key=lambda f: (f.file_path, f.line if f.line is not None else 0, f.rule_id, f.message))
    return findings


def _with_baseline_identities(findings: list[Finding], units: list[AnalysisUnit]) -> list[Finding]:
    """Attach each baseline-eligible finding's durable identity for SARIF code scanning.

    Args:
        findings: This run's findings, before any baseline filtering.
        units: Parsed units, so a declaration is ranked by its own span rather than by the finding's line.

    Returns:
        A new list in input order, with identity and subject set for eligible findings.
        Sensitive findings and findings whose symbols contain the ordinal separator reuse their input objects.
    """
    resolver = declaration_position_from_spans({unit.file.display_path: declaration_spans(unit.tree) for unit in units})
    identities = finding_identities(findings, resolver)
    return [
        finding if named is None else replace(finding, baseline_identity=named.identity, baseline_subject=named.subject)
        for finding, named in zip(findings, identities, strict=True)
    ]


def _filter_suppressed_findings_for_changed_regions(
    suppressed_findings: tuple[SuppressedFinding, ...],
    units: list[AnalysisUnit],
    changed: ChangedRegionSet,
    scope: str,
) -> tuple[SuppressedFinding, ...]:
    """Scope SARIF in-source suppressed findings to the same changed regions as active findings.

    Keeps diff-scoped SARIF uploads aligned with active findings so untouched ``# nosec`` lines do not appear in PR reports.

    Args:
        suppressed_findings: Findings removed by inline comments or duplicate merging; empty returns an empty tuple immediately.
        units: Parsed analysis units used to resolve enclosing declarations under symbol scope; empty skips symbol expansion.
        changed: Resolved changed-region set from ``--diff``, ``--since``, or ``--changed-ranges``; an inactive set returns all entries unchanged.
        scope: Changed-region scope selected by the user (``symbol`` or ``hunk``).

    Returns:
        Suppressed findings whose underlying finding survives changed-region filtering, in input order; empty when none fall in scope.
    """
    # A full scan keeps every suppression row, so SARIF lists them all.
    if not changed.active or not suppressed_findings:
        return suppressed_findings
    kept_ids = {
        id(finding)
        for finding in filter_findings_for_changed_regions(
            [entry.finding for entry in suppressed_findings],
            units,
            changed,
            scope,
        ).findings
    }
    return tuple(entry for entry in suppressed_findings if id(entry.finding) in kept_ids)


def _handle_baseline(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    options: BaselineOptions,
    scan_scope: str,
    units: list[AnalysisUnit],
    changed: ChangedRegionSet | None = None,
) -> tuple[BaselineReport | None, dict[int, str]]:
    """Apply, generate or migrate the baseline requested for this scan.
    Use this before scoring, with declaration positions that keep same-named findings distinct and diagnostics that prevent unsafe writes.

    Args:
        project_root: Project root that baseline paths are resolved against.
        findings: This run's named findings; replaced in place with the surviving findings when a baseline is applied.
        diagnostics: Run diagnostics; option conflicts, baseline errors and identity collisions are appended in place.
        options: The user's baseline flags; conflicts are refused, generation precedes disabling, and disabled skips application.
        scan_scope: Resolved scope label passed to baseline application.
        units: Parsed units whose declaration spans name each finding by its declaration.
        changed: Optional changed-region set; when active, unchanged occurrences spend reviewed counts before changed ones.

    Returns:
        The generated or applied baseline report and any finding classifications. The report is absent when no baseline operation succeeds.
    """
    conflict = _baseline_option_conflict(options)
    # Conflicting flags leave the baseline untouched and put the next action in the report.
    if conflict is not None:
        diagnostics.append(conflict)
        return None, {}
    declaration_position = declaration_position_from_spans({unit.file.display_path: declaration_spans(unit.tree) for unit in units})
    # A generation run saves reviewed counts while leaving the current findings visible for inspection.
    if options.generate_path is not None:
        # A missing operand or invalid line range must never replace an existing review with an incomplete scan.
        if any(diagnostic.invalidates_run is not False for diagnostic in diagnostics):
            return None, {}
        generated = _generate_baseline_safely(
            project_root=project_root,
            findings=findings,
            diagnostics=diagnostics,
            path=options.generate_path,
            migrate_path=options.migrate_path,
            force_overwrite=options.force_overwrite,
            declaration_position=declaration_position,
        )
        return generated, {}
    # `--no-baseline` shows all otherwise reportable findings even when the default baseline exists.
    if options.disabled:
        return None, {}
    return _apply_baseline_if_present(
        project_root=project_root,
        findings=findings,
        diagnostics=diagnostics,
        explicit_path=options.apply_path,
        scan_scope=scan_scope,
        declaration_position=declaration_position,
        changed=changed,
    )


def _reference_only_trees(
    request: AnalysisRunRequest,
    config: AnalysisConfig,
    registry: RuleRegistry,
    scan_scope: str,
    discovery_result: SourceDiscoveryResult,
) -> tuple[ast.Module, ...] | None:
    """Read configured-ignored Python files as references for the unused-export rule.
    A whole-project scan can account for imports from these files without reporting findings on them or ignoring the scan budget.

    Args:
        request: Run request whose paths and ignore flag the second discovery repeats.
        config: Effective configuration carrying the configured ignore globs.
        registry: Rule registry used to confirm the rule that reads references is enabled.
        scan_scope: Resolved scope; only a full-project run has whole-project references to add.
        discovery_result: The run's own discovery, whose files are already analysed units.

    Returns:
        Parsed modules found only when configured globs are dropped, or None when their reference graph is incomplete.
    """
    enabled_rule_ids = {rule.definition().id for rule in registry.enabled_rules(config)}
    # Only a full-project scan that ignores paths, with the reference-reading rule on, has references to add.
    if scan_scope != "full-project" or not config.ignored_path_patterns or ExportedButUnreferencedRule.ID not in enabled_rule_ids:
        return ()
    analysed = {source_file.absolute_path for source_file in discovery_result.files}
    unfiltered = SourceDiscovery(request.project_root).discover(list(request.paths), include_ignored=request.include_ignored)
    parser = PythonFileParser()
    trees: list[ast.Module] = []
    # Successfully parsed Python files removed by the configured globs contribute references, and nothing else is parsed twice.
    for source_file in unfiltered.files:
        # Analysed files contribute through their units, and text files carry no Python references.
        if source_file.absolute_path in analysed or not source_file.is_python():
            continue
        tree = parser.parse(source_file, config.deep_scan_budget).tree
        # An ignored file over the budget could reference an export the analyser would otherwise flag as unused.
        if not isinstance(tree, ast.Module):
            return None
        trees.append(tree)
    return tuple(trees)


def _resolve_scan_scope(request: AnalysisRunRequest, changed: ChangedRegionSet) -> str:
    """Classify the run as full-project or partial for caveats and baseline staleness.

    An active Git diff or patch makes the run partial before rules execute.
    Explicit --changed-ranges filters later, so the requested paths decide its scope.

    Args:
        request: Run request whose changed ranges, paths and project root decide the scope.
        changed: Resolved changed-region set; an active set without explicit changed ranges makes the run partial.

    Returns:
        The scope label partial-scope or full-project.
    """
    if changed.active and request.changed_ranges is None:
        return "partial-scope"
    return _scan_scope(request.paths, request.project_root)


def _scan_scope(paths: tuple[str, ...], project_root: Path) -> str:
    """Classify the requested paths as a full-project or partial scan.

    Spellings such as ./ or src/.. count as full-project when they resolve to the project root.

    Args:
        paths: Requested paths; empty means the whole project.
        project_root: Project root each requested path is resolved against.

    Returns:
        full-project when no paths were given or any path resolves to the project root; otherwise partial-scope.
    """
    if not paths:
        return "full-project"
    root = project_root.resolve()
    if any((root / path).resolve() == root for path in paths):
        return "full-project"
    return "partial-scope"


def _baseline_option_conflict(options: BaselineOptions) -> RunDiagnostic | None:
    """Explain incompatible baseline flags before the scan suppresses findings or writes anything.
    For example, the same invocation cannot apply reviewed counts and generate a replacement baseline.

    Args:
        options: The user's baseline flags to check for incompatible combinations.

    Returns:
        A baseline-error diagnostic for the first conflict found (baseline with generate-baseline, no-baseline with baseline, or migrate-baseline
        without generate-baseline); None when the flags are compatible.
    """
    # Applying reviewed counts and saving a fresh review are separate operations.
    if options.generate_path is not None and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message="--baseline and --generate-baseline are mutually exclusive.",
        )
    # Two opposite baseline choices must not silently cancel each other.
    if options.disabled and options.apply_path is not None:
        return RunDiagnostic(
            type="baseline-error",
            message="--no-baseline cannot be combined with --baseline.",
            path=str(options.apply_path),
        )
    # Migration writes a second file rather than converting one, so it needs the destination the user chose for it.
    if options.migrate_path is not None and options.generate_path is None:
        return RunDiagnostic(
            type="baseline-error",
            message="--migrate-baseline requires --generate-baseline=<new path>; the 0.5 file is never converted in place.",
            path=str(options.migrate_path),
        )
    return None


def _generate_baseline_safely(
    *,
    project_root: Path,
    findings: list[Finding],
    diagnostics: list[RunDiagnostic],
    path: Path,
    migrate_path: Path | None,
    force_overwrite: bool,
    declaration_position: Callable[[Finding], int],
) -> BaselineReport | None:
    """Write the requested baseline, from this run alone or carried across from a 0.5 file, reporting failures in-band.

    Args:
        project_root: Project root the baseline is written for.
        findings: This run's named findings to record.
        diagnostics: Run diagnostics; a baseline failure is appended in place as a baseline-error diagnostic for path.
        path: Destination the new baseline is written to.
        migrate_path: A 0.5 baseline whose reviews are carried into path while the original stays untouched; None generates from this run alone.
        force_overwrite: When true, writing may replace a file at the shared default path that this version would not read, such as a 0.5 baseline;
            otherwise that write is refused.
        declaration_position: Resolver giving the declaration position each finding is named by.

    Returns:
        Report for the written baseline; None when the destination cannot be overwritten or writing or migration failed, with the reason in
        diagnostics.
    """
    try:
        # A generate at the shared default path never destroys a 0.5 baseline by accident; --force is the way to mean it.
        require_overwritable_default_path(project_root, path, force_overwrite)
        # A migration re-identifies the 0.5 reviews from this scan and writes them beside the original, which is untouched.
        if migrate_path is not None:
            return migrate_baseline(
                project_root=project_root,
                input_path=migrate_path,
                output_path=path,
                findings=findings,
                declaration_position=declaration_position,
            )
        return generate_baseline(project_root=project_root, path=path, findings=findings, declaration_position=declaration_position)
    # For example, an unwritable path, or a migration output that is its own input, explains itself without a traceback.
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
    declaration_position: Callable[[Finding], int],
    changed: ChangedRegionSet | None = None,
) -> tuple[BaselineReport | None, dict[int, str]]:
    """Apply reviewed counts from an explicit or discovered baseline.
    A malformed or unreadable baseline becomes a run diagnostic and the scan keeps the findings the file would have hidden.

    Args:
        project_root: Project root whose default baseline is looked up when no explicit path is given.
        findings: This run's named findings; replaced in place with the findings the baseline leaves visible.
        diagnostics: Run diagnostics; baseline errors and identity collisions are appended in place.
        explicit_path: Baseline path the user supplied; None uses the default baseline when that file exists.
        scan_scope: Resolved scope label passed to baseline application.
        declaration_position: Resolver giving the declaration position each finding is named by.
        changed: Optional changed-region set; when active, unchanged occurrences spend reviewed counts before changed ones.

    Returns:
        The applied baseline report and per-finding classifications, or no report and an empty map when no baseline was applied.
    """
    selected_path, source = _resolve_baseline_selection(project_root, explicit_path)
    # With no baseline to apply, findings have no reviewed or new status for the exit gate.
    if selected_path is None:
        return None, {}
    # During a changed-code scan, let untouched occurrences spend baseline credit before newly edited lines.
    is_changed = (lambda finding: is_finding_location_changed(finding, changed)) if (changed is not None and changed.active) else None
    try:
        result = apply_baseline(
            project_root=project_root,
            path=selected_path,
            findings=findings,
            source=source,
            scan_scope=scan_scope,
            declaration_position=declaration_position,
            is_in_changed_region=is_changed,
        )
    # For example, invalid JSON, a 0.5 layout, or another port's file becomes a diagnostic and leaves findings intact.
    except BaselineError as exc:
        diagnostics.append(RunDiagnostic(type="baseline-error", message=str(exc), path=str(selected_path)))
        return None, {}
    diagnostics.extend(collision_diagnostics(result.collisions))
    findings[:] = result.findings
    return result.report, result.statuses


def collision_diagnostics(collisions: tuple[BaselineCollision, ...]) -> list[RunDiagnostic]:
    """Name every identity shared by multiple declarations so users can identify findings the baseline cannot distinguish.

    No colliding finding is suppressed, so one review cannot hide another declaration's finding.

    Args:
        collisions: Identity collisions found while applying the baseline.

    Returns:
        One baseline-collision diagnostic per collision, each marked as not invalidating the run and naming the identity, subjects, rule and path;
        empty when there are none.
    """
    return [
        RunDiagnostic(
            type="baseline-collision",
            message=(
                f"collision: identity {collision.identity} covers {len(collision.subjects)} declarations of "
                f"{', '.join(collision.subjects)} for rule {collision.rule_id} in {collision.path}; none is suppressed"
            ),
            file_path=collision.path,
            invalidates_run=False,
        )
        for collision in collisions
    ]


def _resolve_baseline_selection(project_root: Path, explicit_path: Path | None) -> tuple[Path | None, str]:
    """Choose the explicit or default baseline path a user asked the scan to apply.

    Args:
        project_root: Project root whose default baseline file is checked.
        explicit_path: Baseline path the user supplied; when given it is returned without checking that it exists.

    Returns:
        Tuple (path, source) with source explicit or default; the default baseline is returned as its bare file name, and path is None when no default
        baseline file exists.
    """
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
    """Load settings for this request and preserve the config source and warnings for users.

    Args:
        project_root: Project root the config loader searches from.
        config_path: Explicit config path; None lets the loader discover the project config.
        no_config: When true, no config file is read and registry defaults apply; combined with config_path it produces a config-error diagnostic
            instead.
        registry: Rule registry the default configuration is built from.
        strict_config: When true, any problem the loader would record as a warning stops the load with a ConfigError instead.

    Returns:
        Tuple of the effective config, selected config file path, diagnostics list and loader warnings. Without a selected config source, the path is
        None and the config uses registry defaults. The diagnostics list is empty unless no_config conflicts with config_path.
    """
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
    """Parse discovered files and retain parse failures for the final CLI report.

    Args:
        source_files: Discovered files in scan order.
        deep_scan_budget: Line and byte budget the parser applies to each file.

    Returns:
        The tuple contains one unit per source file, the count of units without fatal parser diagnostics, and file-tagged parser diagnostics.
        The count includes non-Python files read as text and Python files whose deep scan was skipped. Non-fatal diagnostics leave the run valid.
    """
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
    """Turn requested paths that do not exist into diagnostics users can act on.

    Args:
        missing_paths: Requested paths that discovery could not find.

    Returns:
        One missing-path diagnostic per path; empty when every requested path exists.
    """
    return [RunDiagnostic(type="missing-path", message="path not found", path=missing) for missing in missing_paths]


def _parse_suppressions(
    units: list[AnalysisUnit],
    registry: RuleRegistry,
) -> dict[str, ParsedSuppressions]:
    """Parse inline suppression directives before findings are prepared for the user.

    Args:
        units: Parsed units; a unit with no source or a bounded deep scan is skipped.
        registry: Rule registry whose full rule list, disabled rules included, defines the rule ids a directive may name.

    Returns:
        Parsed directives keyed by display path; skipped units have no entry.
    """
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
    """Expose malformed or unknown suppression directives alongside scan findings.

    Args:
        suppressions_by_file: Parsed suppression directives keyed by display path.

    Returns:
        Parser diagnostics tagged with file paths and lines; a directive can yield multiple errors. Empty when no errors were recorded.
    """
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
    *,
    min_confidence: Confidence = Confidence.LOW,
    new_statuses: Mapping[int, str] | None = None,
) -> int:
    """Turn the scan's diagnostics and findings into the status returned to the caller.
    Fatal diagnostics take precedence. Presentation filters do not affect the severity or new-finding gates.

    Args:
        findings: Findings remaining after suppression, baseline and changed-region handling, before display filtering.
        diagnostics: Run-level diagnostics (config errors, parse failures, missing paths).
        fail_threshold: Effective failure threshold after any command-specific configuration override.
        min_confidence: Lowest confidence that reaches the severity gate.
        new_statuses: Applied baseline classifications. None or an empty map leaves only the severity and confidence gate.

    Returns:
        2 for invalidating diagnostics, 1 for a finding that reaches either gate, and 0 otherwise.
    """
    # An unreadable input is a failed scan even if no findings are available to gate on.
    if any(diagnostic.invalidates_run is not False for diagnostic in diagnostics):
        return 2
    # Any retained finding can block CI, including one hidden by the eventual display filter.
    for finding in findings:
        # Unreviewed findings under an applied baseline (new, collision, or baseline-ineligible) trigger --fail-on-new.
        if new_statuses is not None and is_unreviewed_baseline_status(new_statuses.get(id(finding))):
            return 1
        # The ordinary gate requires both the chosen severity and the minimum confidence.
        if fail_threshold.is_triggered_by(finding.severity) and finding.confidence.meets(min_confidence):
            return 1
    return 0


def _apply_deep_scan_budget_override(
    config: AnalysisConfig,
    value: str,
) -> AnalysisConfig:
    """Apply the atomic CLI budget after config so both limits share provenance.

    Args:
        config: Effective configuration after the config file is applied.
        value: Deep-scan budget option value: empty keeps the configured budget, off disables the budget while keeping the configured limits, and
            LINES:BYTES enables the budget with both limits set.

    Returns:
        The config unchanged when value is empty; otherwise a copy whose deep-scan budget carries the CLI override.

    Raises:
        ConfigError: When value is not empty, not off, and not two positive integers in LINES:BYTES form.
    """
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
