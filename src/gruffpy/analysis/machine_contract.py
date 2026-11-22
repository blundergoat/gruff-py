"""Build the shared JSON envelopes for `analyse`, `report` and `summary`.

Automation gets project-relative paths and the run data needed to interpret findings.
The serializer uses the completed scan so JSON readers get the same analysis result as terminal users.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gruffpy.analysis.baseline import BaselineReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION, SUMMARY_SCHEMA_VERSION
from gruffpy.analysis.suppression_summary import SuppressionSummary
from gruffpy.finding.finding import Finding
from gruffpy.scoring.score_report import ScoreReport
from gruffpy.source.discovery import (
    IGNORE_SOURCE_CONFIG,
    IGNORE_SOURCE_DEFAULT,
    IGNORE_SOURCE_GENERATED,
    IGNORE_SOURCE_GITIGNORE,
    IgnoredPath,
)
from gruffpy.version import TOOL_NAME

if TYPE_CHECKING:
    from gruffpy.analysis.report import AnalysisReport


_DEFAULT_SKIP_REASONS = {
    "*.min.*": "generated",
    ".fleet": "local-tooling",
    ".git": "vcs",
    ".hg": "vcs",
    ".idea": "local-tooling",
    ".mypy_cache": "tool-cache",
    ".pyre": "tool-cache",
    ".pytest_cache": "tool-cache",
    ".pytype": "tool-cache",
    ".ruff_cache": "tool-cache",
    ".svn": "vcs",
    ".tox": "tool-cache",
    ".venv": "dependency",
    ".vscode": "local-tooling",
    "__pycache__": "tool-cache",
    "bower_components": "dependency",
    "build": "build-output",
    "coverage": "build-output",
    "dist": "build-output",
    "htmlcov": "build-output",
    "node_modules": "dependency",
    "third-party": "dependency",
    "third_party": "dependency",
    "vendor": "dependency",
    "vendors": "dependency",
    "venv": "dependency",
}


def analysis_payload(report: AnalysisReport) -> dict[str, Any]:
    """Return one canonical gruff.analysis.v3 document.

    Summary finding counts use machine_context.summary_findings when set, including an empty tuple. None uses report.findings.

    Args:
        report: Supplies run settings, diagnostics and emitted findings, plus a separate findings sequence for summary counts when available.

    Returns:
        JSON-compatible analysis envelope with shared fields and Python extensions.
    """
    details, ignored_paths = _machine_ignored_paths(report)
    summary_findings = report.machine_context.summary_findings
    if summary_findings is None:
        summary_findings = report.findings
    payload: dict[str, Any] = {
        "schemaVersion": ANALYSIS_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": report.tool_version},
        "run": _machine_run(report),
        "summary": _machine_summary(report, summary_findings, details),
        "score": _machine_score(report.score, report.machine_context.project_root),
        "diagnostics": [_machine_diagnostic(item, report.machine_context.project_root) for item in report.diagnostics],
        "findings": [_machine_finding(item, report.machine_context.project_root) for item in report.findings],
        "paths": {
            "analysedFiles": report.files_parsed,
            "details": details,
            "ignoredPaths": ignored_paths,
            # An unresolved symlink still has a diagnostic, even when its location cannot be published.
            "missingPaths": _machine_inputs(
                report.missing_paths,
                report.machine_context.project_root,
            ),
        },
        "suppressions": [_machine_suppression(item, report.machine_context.project_root) for item in report.suppressions],
    }
    _add_optional_sections(payload, report)
    return payload


def summary_payload(report: AnalysisReport) -> dict[str, Any]:
    """Return analysis v3 with only findings removed and its schema changed.

    Args:
        report: Native run state used for the analysis projection.

    Returns:
        Exact findings-free summary projection of the analysis envelope.
    """
    payload = analysis_payload(report)
    payload["schemaVersion"] = SUMMARY_SCHEMA_VERSION
    del payload["findings"]
    return payload


def _machine_run(report: AnalysisReport) -> dict[str, Any]:
    """Present the settings and operands that shaped this scan.
    Automation can use this section to distinguish runs with different paths, display filters or coverage limits.

    Args:
        report: Native run state supplying the fail-on level, output format, requested paths, config path, filters, configuration warnings and
            partial-context caveat, plus the machine context's project root and include-ignored flag.

    Returns:
        JSON-compatible run object with failOn, format and inputs, and with projectRoot set to a dot.
        Includes config when projectable, filters when active, includeIgnored when true and extensions when populated.
    """
    root = report.machine_context.project_root
    payload: dict[str, Any] = {
        "failOn": report.fail_on,
        "format": report.format,
        "inputs": _machine_inputs(report.requested_paths, root),
        "projectRoot": ".",
    }
    # Runs using defaults have no config file to name.
    if report.config_path is not None:
        config_path = project_relative_path(report.config_path, root)
        # An explicit config may live outside the checkout, so only a project path is published.
        if config_path is not None:
            payload["config"] = config_path
    # Record a requested display filter separately so readers can tell presentation settings from rule selection.
    if report.filters is not None and report.filters.is_active():
        payload["filters"] = _machine_run_filters(report.filters.to_dict())
    # Record when the operator deliberately scanned paths the default discovery rules would skip.
    if report.machine_context.include_ignored:
        payload["includeIgnored"] = True
    native: dict[str, Any] = {}
    # A scan can proceed after disregarding a bad rule setting, so keep that warning with the result.
    if report.config_warnings:
        native["configWarnings"] = list(report.config_warnings)
    # Project-wide rules may have incomplete evidence when the user asks for a diff or a narrow target.
    if report.partial_context_caveat is not None:
        native["partialContextCaveat"] = report.partial_context_caveat
    # Omit the Python extension when there are no native warnings or caveats to show.
    if native:
        payload["extensions"] = {"py": {"run": native}}
    return payload


def _machine_run_filters(values: dict[str, object]) -> dict[str, object]:
    """Normalise the filter dictionary into the run.filters object, keeping only string entries in each rule and pillar list.

    Args:
        values: Dictionary from the filter's to_dict, carrying active and the four include and exclude lists, and optionally minSeverity.

    Returns:
        Filters object with active coerced to a boolean, each list reduced to its string items (empty when the value is not a list), and minSeverity
        only when it is a non-empty string.
    """
    payload: dict[str, object] = {
        "active": bool(values["active"]),
        "excludePillars": _machine_string_list(values["excludePillars"]),
        "excludeRules": _machine_string_list(values["excludeRules"]),
        "includePillars": _machine_string_list(values["includePillars"]),
        "includeRules": _machine_string_list(values["includeRules"]),
    }
    minimum = values.get("minSeverity")
    if isinstance(minimum, str) and minimum:
        payload["minSeverity"] = minimum
    return payload


def _machine_string_list(value: object) -> list[str]:
    """Coerce an untyped filter value into a list of its string items.

    Args:
        value: Value read from the filter dictionary; anything other than a list yields an empty result.

    Returns:
        The string items of value in their original order, or an empty list when value is not a list.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _machine_summary(
    report: AnalysisReport,
    findings: tuple[Finding, ...],
    details: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the summary section of the envelope from file, path, diagnostic and finding counts.

    analysedFiles and parsedFiles both report files_parsed, and ignoredPaths and skippedFiles both report the number of ignored-path details.
    suppressedFindings appears only when the report recorded a suppressed count.

    Args:
        report: Native run state supplying file counts, diagnostics, missing paths, parse errors, exit code and the suppressed count.
        findings: Findings to count by severity and pillar; analysis_payload passes the machine context's summary findings when set, otherwise the
            reported findings.
        details: Ignored-path detail objects already built for the paths section, counted for ignoredPaths and skippedFiles.

    Returns:
        JSON-compatible summary object of run counts.
    """
    payload: dict[str, Any] = {
        "analysedFiles": report.files_parsed,
        "diagnostics": len(report.diagnostics),
        "discoveredFiles": report.files_discovered,
        "exitCode": report.exit_code,
        "findings": _finding_counts(findings),
        "findingsByPillar": _finding_counts_by_pillar(findings),
        "ignoredPaths": len(details),
        "missingPaths": len(report.missing_paths),
        "parseErrors": report.parse_error_count(),
        "parsedFiles": report.files_parsed,
        "skippedFiles": len(details),
    }
    if report.suppressed_count is not None:
        payload["suppressedFindings"] = report.suppressed_count
    return payload


def _finding_counts(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Count findings per severity alongside their total.

    Args:
        findings: Findings to tally by severity.

    Returns:
        Mapping with advisory, warning and error counts, each zero when no finding has that severity, and total set to the number of findings.
    """
    counts = {"advisory": 0, "warning": 0, "error": 0, "total": len(findings)}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _finding_counts_by_pillar(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Count findings per primary pillar, ordered by pillar name.

    Only pillars with at least one finding appear, and secondary pillars are not counted.

    Args:
        findings: Findings to tally by their primary pillar.

    Returns:
        Mapping from pillar value to finding count sorted by key, or an empty mapping when there are no findings.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.pillar.value] = counts.get(finding.pillar.value, 0) + 1
    return dict(sorted(counts.items()))


def _machine_finding(finding: Finding, root: str) -> dict[str, Any]:
    """Project one native finding into the shared machine finding object with a root-relative file path.

    Metadata is copied with locationPrecision set to scanner-pinpointed for a positive column, otherwise line-only; the finding is unchanged.
    Missing or nonpositive lines become 1. The object omits missing or nonpositive end lines and columns, and missing or empty symbols.

    Args:
        finding: Supplies the rule, message, location, fingerprints and metadata for the machine finding.
        root: Project root that the finding's file path is made relative to.

    Returns:
        JSON-compatible finding object with ruleId, message, file, line, severity, pillar, secondaryPillars, tier, confidence, remediation (empty
        string when absent), fingerprint, stableIdentity and metadata, plus endLine, column and symbol when they apply.

    Raises:
        ValueError: The finding path cannot be represented relative to the project root.
    """
    metadata = dict(finding.metadata)
    has_column = finding.column is not None and finding.column > 0
    metadata["locationPrecision"] = "scanner-pinpointed" if has_column else "line-only"
    payload: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "message": finding.message,
        "file": _machine_path(finding.file_path, root),
        "line": max(1, finding.line or 1),
        "severity": finding.severity.value,
        "pillar": finding.pillar.value,
        "secondaryPillars": [pillar.value for pillar in finding.secondary_pillars],
        "tier": finding.tier.value,
        "confidence": finding.confidence.value,
        "remediation": finding.remediation or "",
        "fingerprint": finding.fingerprint(),
        "stableIdentity": finding.stable_identity(),
        "metadata": metadata,
    }
    if finding.end_line is not None and finding.end_line > 0:
        payload["endLine"] = finding.end_line
    if has_column:
        payload["column"] = finding.column
    if finding.symbol:
        payload["symbol"] = finding.symbol
    return payload


def _machine_diagnostic(diagnostic: RunDiagnostic, root: str) -> dict[str, Any]:
    """Publish a diagnostic so automation can explain an incomplete or failed scan.
    A missing fatality flag defaults to fatal. Source locations appear only when a project-relative file or a positive line is available.

    Args:
        diagnostic: Entry from report.diagnostics supplying the message, location and whether the problem invalidates the run.
        root: Project root used to make the diagnostic's file path relative.

    Returns:
        JSON-compatible diagnostic object with type, message, invalidatesRun and, when available, file and line.
    """
    payload: dict[str, Any] = {
        "type": diagnostic.type,
        "message": diagnostic.message,
        "invalidatesRun": (True if diagnostic.invalidates_run is None else diagnostic.invalidates_run),
    }
    # A config or startup error can be useful even when there is no publishable file location.
    if (file_path := diagnostic_file_path(diagnostic, root)) is not None:
        payload["file"] = file_path
    # Whole-file failures carry no line to open in an editor.
    if diagnostic.line is not None and diagnostic.line > 0:
        payload["line"] = diagnostic.line
    return payload


def diagnostic_file_path(diagnostic: RunDiagnostic, root: str) -> str | None:
    """Find the project-relative location shared by JSON, hook and SARIF diagnostics.
    Use the source file when available, or the input path when the failure happened before the analyser opened a file.

    Args:
        diagnostic: Run problem whose file path takes precedence over its input path. When both are missing, readers get the message alone.
        root: Project root the location is relative to.

    Returns:
        A POSIX path within the project, or None when the location cannot be published.
    """
    source_path = diagnostic.file_path or diagnostic.path
    return project_relative_path(source_path, root) if source_path else None


def _machine_ignored_paths(
    report: AnalysisReport,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build the sorted ignored-path details and the ignored path list, and require both to name the same paths in the same order.

    Detail paths are sorted after projection. The ignored path list keeps the first occurrence of each root-relative path. Those first occurrences
    must be in sorted order and match the detail paths one for one.

    Args:
        report: Native run state supplying ignored_path_details, ignored_paths and the project root.

    Returns:
        Pair of the machine detail objects sorted by path and the root-relative ignored path list.

    Raises:
        ValueError: When the ignored path list and the detail paths differ in membership or order.
    """
    root = report.machine_context.project_root
    details = [_machine_path_detail(item, root) for item in report.ignored_path_details]
    details.sort(key=lambda item: item["path"])
    ignored_paths = _machine_paths(report.ignored_paths, root)
    detail_paths = [str(item["path"]) for item in details]
    if ignored_paths != detail_paths:
        raise ValueError("ignored paths and their machine details must have identical paths")
    return details, ignored_paths


def _machine_path_detail(detail: IgnoredPath, root: str) -> dict[str, Any]:
    """Project one ignored path into a machine detail object carrying its path, canonical reason and source.

    pattern appears only when the record carries a non-empty pattern. A path outside the project root, or a source and pattern with no canonical
    reason, propagates ValueError from the path and reason helpers.

    Args:
        detail: Ignored path record from discovery.
        root: Project root the path is made relative to.

    Returns:
        JSON-compatible object with path, reason, source and, when set, pattern.
    """
    payload: dict[str, Any] = {
        "path": _machine_path(detail.path, root),
        "reason": _skip_reason(detail),
        "source": detail.source,
    }
    if detail.pattern:
        payload["pattern"] = detail.pattern
    return payload


def _skip_reason(detail: IgnoredPath) -> str:
    """Map an ignored path's source and pattern to the canonical skip reason published in machine output.

    Config, gitignore and generated sources map directly to config-ignore, gitignored and generated; a default ignore takes the reason listed for its
    pattern in _DEFAULT_SKIP_REASONS.

    Args:
        detail: Ignored path record whose source and pattern select the reason.

    Returns:
        Canonical reason string such as config-ignore, gitignored, generated, vcs, tool-cache, dependency, local-tooling or build-output.

    Raises:
        ValueError: When the source is not one of the four known ignore sources, or a default ignore's pattern has no entry in the canonical reason
            table.
    """
    if detail.source == IGNORE_SOURCE_CONFIG:
        return "config-ignore"
    if detail.source == IGNORE_SOURCE_GITIGNORE:
        return "gitignored"
    if detail.source == IGNORE_SOURCE_GENERATED:
        return "generated"
    if detail.source != IGNORE_SOURCE_DEFAULT or detail.pattern not in _DEFAULT_SKIP_REASONS:
        raise ValueError(f"ignored path {detail.path!r} has no canonical reason for {detail.source!r}/{detail.pattern!r}")
    return _DEFAULT_SKIP_REASONS[detail.pattern]


def _machine_suppression(summary: SuppressionSummary, root: str) -> dict[str, Any]:
    """Project one suppression summary row into the machine suppression object.

    Paths become unique and root-relative. Empty symbols and a None source are omitted.
    Source is built-in for test-path skips, inline for another tool's comment or duplicate for a merged claim.

    Args:
        summary: Audit row supplying the rule, suppression reason and count. Configured exclusions carry no source.
        root: Project root the suppression's paths are made relative to.

    Returns:
        JSON-compatible object with index, rule, paths, reason, suppressed count and, when present, symbol and source.
    """
    payload: dict[str, Any] = {
        "index": summary.index,
        "rule": summary.rule,
        "paths": _machine_paths(summary.paths, root),
        "reason": summary.reason,
        "suppressed": summary.suppressed,
    }
    if summary.symbol:
        payload["symbol"] = summary.symbol
    if summary.source is not None:
        payload["source"] = summary.source
    return payload


def _machine_score(score: ScoreReport | None, root: str) -> dict[str, Any]:
    """Project the score report into the machine score section, or a null-graded placeholder when no scoring ran.

    Without a score the composite grade and score are null so no failing grade is implied, and coverage carries a caveat that no score was produced. A
    real score whose composite is None also yields a null grade and score.

    Args:
        score: Score report for the run, or None when no scoring ran.
        root: Project root used to make top-offender file paths relative.

    Returns:
        JSON-compatible score object; the placeholder carries coverage but no complexityDistribution, scope or explanation, while a real score carries
        those three but no coverage.
    """
    if score is None:
        return {
            # No scoring ran, so there is no number to report; a 0.0 would read as a failing grade.
            "composite": {"grade": None, "score": None},
            "clusters": [],
            "ruleAttribution": [],
            "evaluatedFiles": None,
            "scoredPillars": [],
            "pillars": [],
            "topOffenders": [],
            "coverage": {
                "contributingPillars": [],
                "caveat": "No score was produced for this run.",
            },
        }
    return {
        "composite": {
            "grade": None if score.composite is None else score.composite.letter,
            "score": None if score.composite is None else score.composite.score,
        },
        "clusters": [dict(cluster) for cluster in score.clusters],
        "ruleAttribution": [dict(row) for row in score.rule_attribution],
        "evaluatedFiles": score.evaluated_files,
        "scoredPillars": list(score.scored_pillars),
        "pillars": [_machine_pillar_score(item) for item in score.pillars],
        "topOffenders": [_machine_file_score(item, root) for item in score.top_offenders],
        "complexityDistribution": dict(score.complexity_distribution),
        "scope": score.scope,
        "explanation": score.explanation,
    }


def _machine_pillar_score(score: Any) -> dict[str, Any]:
    """Project one pillar's score into the machine pillar object with its penalty rounded to two decimals.

    Args:
        score: PillarScore taken from the score report's pillars.

    Returns:
        JSON-compatible object with the pillar, finding and per-severity counts, applicability, rounded penalty, and grade letter and score, both null
        when the pillar has no grade.
    """
    payload: dict[str, Any] = {
        "pillar": score.pillar,
        "findings": score.findings,
        "penalty": round(score.penalty, 2),
        "advisory": score.advisories,
        "warning": score.warnings,
        "error": score.errors,
        "applicable": score.applicable,
        "grade": None if score.grade is None else score.grade.letter,
        "score": None if score.grade is None else score.grade.score,
    }
    return payload


def _machine_file_score(score: Any, root: str) -> dict[str, Any]:
    """Project one top-offender file score into the machine object with a root-relative file path.

    maxCyclomatic, maxCognitive, maxLines and mutationScore appear only when the file score carries them.

    Args:
        score: FileScore taken from the score report's top offenders.
        root: Project root the file path is made relative to.

    Returns:
        JSON-compatible object with file, finding and per-severity counts, grade letter and score (null when ungraded), rounded penalty, and
        maxCyclomatic, maxCognitive, maxLines and mutationScore when present.
    """
    payload: dict[str, Any] = {
        "file": _machine_path(score.file_path, root),
        "findings": score.findings,
        "advisory": score.advisories,
        "warning": score.warnings,
        "error": score.errors,
        "grade": None if score.grade is None else score.grade.letter,
        "score": None if score.grade is None else score.grade.score,
        "penalty": round(score.penalty, 2),
    }
    optional = {
        "maxCyclomatic": score.max_cyclomatic,
        "maxCognitive": score.max_cognitive,
        "maxLines": score.max_lines,
        "mutationScore": score.mutation_score,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})
    return payload


def _add_optional_sections(payload: dict[str, Any], report: AnalysisReport) -> None:
    """Add the baseline, diff, displayFilter and extensions sections to the envelope when the run produced them.

    Mutates payload in place, setting each key only when its projection is present or non-empty.

    Args:
        payload: Analysis envelope being built, mutated in place.
        report: Native run state supplying the baseline, diff, display filter and extension values.

    Returns:
        None. Adds the applicable sections to payload in place.
    """
    baseline = _machine_baseline(report.extensions.baseline, report.machine_context.project_root)
    if baseline is not None:
        payload["baseline"] = baseline
    diff = _machine_diff(report.extensions.diff, report.machine_context.project_root)
    if diff is not None:
        payload["diff"] = diff
    display_filter = _machine_display_filter(report)
    if display_filter is not None:
        payload["displayFilter"] = display_filter
    extensions = _machine_extensions(report)
    if extensions:
        payload["extensions"] = extensions


def _machine_baseline(value: Any, root: str) -> dict[str, Any] | None:
    """Explain how the run used reviewed findings in the JSON report.
    Generation is recorded separately from matching. The output distinguishes entries still present from those now absent.

    Args:
        value: Baseline extension value from the report; anything other than a BaselineReport means there is no baseline section.
        root: Project root used to make the baseline file path relative.

    Returns:
        JSON-compatible baseline object, or None when value is not a BaselineReport.
    """
    # A scan that skips or never reaches baseline handling has no baseline section.
    if not isinstance(value, BaselineReport):
        return None
    payload: dict[str, Any] = {
        "applied": not value.generated,
        "entries": value.total_entries,
        "generated": value.generated,
        "newFindings": value.new_count + value.collision_count + value.not_eligible_count,
        "resolvedFindings": value.absent_count,
        "source": value.source,
        "stale": [_machine_baseline_entry(item, root) for item in value.stale_entries],
        "staleEntries": len(value.stale_entries),
        "staleEvaluation": value.stale_evaluation,
        "suppressedFindings": value.suppressed_findings,
        "unchangedFindings": value.unchanged_count,
    }
    path = project_relative_path(value.path, root)
    # An externally stored baseline can still affect the result without publishing its location.
    if path is not None:
        payload["path"] = path
    return payload


def _machine_baseline_entry(value: Any, root: str) -> dict[str, Any]:
    """Describe a reviewed row whose count is no longer needed in this scan.
    The identity and count let automation explain the change. Optional descriptions help a human recognise the original finding.

    Args:
        value: Stale baseline entry from the baseline report, carrying an identity, a count and optional rule, path and subject.
        root: Project root used to normalize the recorded path.

    Returns:
        JSON-compatible object with identity and count, optional ruleId and subject, and a path only if it lies in the project.
    """
    payload: dict[str, Any] = {"identity": value.identity, "count": value.count}
    # Older or hand-edited rows may carry only an identity and count, which are enough for matching.
    for field_name, label in (("ruleId", value.rule_id), ("path", project_relative_path(value.path, root)), ("subject", value.subject)):
        # Empty labels add no location or description for a reviewer.
        if label:
            payload[field_name] = label
    return payload


def _machine_diff(value: Any, root: str) -> dict[str, Any] | None:
    """Project the diff extension into the machine diff section when diff mode was enabled.

    A callable to_dict supplies the native value. Missing changedFiles yields no paths; missing suppressedCount yields zero filteredFindings.
    Otherwise suppressedCount is converted to int. mode requires non-empty string source; caveat requires a string and may be empty.

    Args:
        value: Diff extension value from the report, either an object with to_dict or a dictionary, or None when no diff was requested.
        root: Project root used to make the changed file paths relative and de-duplicate them.

    Returns:
        JSON-compatible diff object with the changed file count and paths, enabled true and the filtered finding count, or None when the value is not
        a dictionary or diff mode is not enabled.
    """
    native = _to_report_value(value)
    if not isinstance(native, dict) or not native.get("enabled"):
        return None
    changed_files = _machine_paths(native.get("changedFiles", []), root)
    payload: dict[str, Any] = {
        "changedFileCount": len(changed_files),
        "changedFiles": changed_files,
        "enabled": True,
        "filteredFindings": int(native.get("suppressedCount", 0)),
    }
    mode = native.get("source")
    if isinstance(mode, str) and mode:
        payload["mode"] = mode
    caveat = native.get("caveat")
    if isinstance(caveat, str):
        payload["caveat"] = caveat
    return payload


def _machine_display_filter(report: AnalysisReport) -> dict[str, Any] | None:
    """Project the active display filter into the machine displayFilter section.

    Args:
        report: Native run state supplying the filters and the count of findings they hid.

    Returns:
        Object with applied true, the four include and exclude lists and hiddenFindings, or None when no filter is set or it is inactive.
    """
    if report.filters is None or not report.filters.is_active():
        return None
    values = report.filters.to_dict()
    return {
        "applied": True,
        "excludePillars": list(values["excludePillars"]),
        "excludeRules": list(values["excludeRules"]),
        "hiddenFindings": report.hidden_by_display_filter,
        "includePillars": list(values["includePillars"]),
        "includeRules": list(values["includeRules"]),
    }


def _machine_extensions(report: AnalysisReport) -> dict[str, Any]:
    """Collect the Python-only mutation, review and trend values under extensions.py.topLevel.

    Args:
        report: Native run state whose mutation, review and trend extensions are converted to report values.

    Returns:
        Extensions object holding only the values that are set, or an empty dict when none are, so the caller omits the section.
    """
    top_level = {
        key: _to_report_value(value)
        for key, value in {
            "mutation": report.extensions.mutation,
            "review": report.extensions.review,
            "trend": report.extensions.trend,
        }.items()
        if value is not None
    }
    return {} if not top_level else {"py": {"topLevel": top_level}}


def _to_report_value(value: Any) -> Any:
    """Use the report representation supplied by an extension's callable to_dict method.

    Args:
        value: Report extension to convert through a callable to_dict, or preserve unchanged when no such method exists.

    Returns:
        The result of value.to_dict() when callable. Otherwise returns value unchanged, including None for a missing extension.
    """
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value


def _machine_paths(values: Any, root: str) -> list[str]:
    """Make every path root-relative and de-duplicate them in first-seen order, refusing any path outside the project root.

    Unlike _machine_inputs, a path that cannot be expressed under the root propagates ValueError from _machine_path instead of being dropped.

    Args:
        values: Iterable of paths, each converted with str before projection.
        root: Project root the paths are made relative to.

    Returns:
        Root-relative POSIX paths without duplicates, in first-seen order.
    """
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        path = _machine_path(str(value), root)
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _machine_inputs(values: Any, root: str) -> list[str]:
    """Publish unique paths suitable for the JSON report.
    The scan can report a startup failure without disclosing an external location or failing on an unresolved input.

    Args:
        values: Requested input paths, each converted with str before projection.
        root: Project root, or the launch directory when the run never resolved one.

    Returns:
        Root-relative POSIX input paths without duplicates, in first-seen order, with inputs outside the root omitted.
    """
    paths: list[str] = []
    seen: set[str] = set()
    # Keep the order in which the user named inputs so a refusal report still reflects the invocation.
    for value in values:
        path = project_relative_path(str(value), root)
        # Repeated spellings of the same file and inputs without a publishable path need no list entry.
        if path is not None and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _machine_path(value: str, root: str) -> str:
    """Require a project-relative path for a field whose contract needs a location.
    Use this for findings and other records that cannot be published safely without a valid path.

    Args:
        value: Absolute path, or path relative to root, to project.
        root: Project root the path is made relative to.

    Returns:
        Root-relative POSIX path.

    Raises:
        ValueError: When the path is empty, uses a foreign path style, or resolves outside the project root.
    """
    path = project_relative_path(value, root)
    # Mandatory location fields cannot safely represent a finding outside the selected project.
    if path is None:
        raise ValueError(f"machine path {value!r} is outside the project root")
    return path


def project_relative_path(value: str, root: str) -> str | None:
    """Convert an input into a portable path inside the selected project.
    Resolve links before publishing a location so a symlink cannot expose a file outside the checkout.

    Args:
        value: Absolute path, or path relative to root, to project.
        root: Project root the result is relative to.

    Returns:
        A root-relative POSIX path, or . for the root itself.
        None when the path is empty, uses a foreign path style, or resolves outside the project root.
        None also covers resolution errors such as an unlistable directory or a symlink loop in the input.
    """
    # A Linux reader cannot anchor a Windows drive path, and an empty input offers no location.
    if not value or (os.name != "nt" and ("\\" in value or re.match(r"^[A-Za-z]:", value))):
        return None
    root_path = Path(root).resolve()
    candidate = Path(value)
    # A Windows spelling such as `C:source.py` depends on the caller's drive-specific working directory.
    if candidate.drive and not candidate.is_absolute():
        return None
    # For example, `src/app.py` is resolved from the project selected for this scan.
    if not candidate.is_absolute():
        candidate = root_path / candidate
    try:
        relative = candidate.resolve().relative_to(root_path)
    except (OSError, RuntimeError, ValueError):
        # A circular link or a link outside the checkout has no location the report can publish safely.
        return None
    return relative.as_posix()
