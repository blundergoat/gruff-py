"""Project native analysis state into the shared v3 machine contracts."""

from __future__ import annotations

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
    """Return one canonical ``gruff.analysis.v3`` document.

    Args:
        report: Native run state to project without changing analysis semantics.

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
            "missingPaths": _machine_paths(
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
    """Build the run section of the analysis envelope from the report's settings, with inputs and config path made relative to the project root.

    The config path and any input that cannot be expressed under the project root are omitted rather than published as host paths. Filters appear only
    when active, includeIgnored only when true, and configuration warnings and the partial-context caveat go under extensions.py.run only when
    present.

    Args:
        report: Native run state supplying the fail-on level, output format, requested paths, config path, filters, configuration warnings and
            partial-context caveat, plus the machine context's project root and include-ignored flag.

    Returns:
        JSON-compatible run object with failOn, format, inputs and projectRoot set to ., plus config, filters, includeIgnored and extensions only when
        they apply.
    """
    root = report.machine_context.project_root
    payload: dict[str, Any] = {
        "failOn": report.fail_on,
        "format": report.format,
        "inputs": _machine_inputs(report.requested_paths, root),
        "projectRoot": ".",
    }
    if report.config_path is not None:
        config_path = _machine_relative_path(report.config_path, root)
        if config_path is not None:
            payload["config"] = config_path
    if report.filters is not None and report.filters.is_active():
        payload["filters"] = _machine_run_filters(report.filters.to_dict())
    if report.machine_context.include_ignored:
        payload["includeIgnored"] = True
    native: dict[str, Any] = {}
    if report.config_warnings:
        native["configWarnings"] = list(report.config_warnings)
    if report.partial_context_caveat is not None:
        native["partialContextCaveat"] = report.partial_context_caveat
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

    The finding's metadata is copied and given locationPrecision, scanner-pinpointed when a positive column exists and line-only otherwise, so the
    finding itself is not mutated. The line is clamped to at least 1, endLine and column appear only when set and positive, and symbol only when
    non-empty. A file outside the project root propagates the ValueError from _machine_path.

    Args:
        finding: Native finding to project.
        root: Project root that the finding's file path is made relative to.

    Returns:
        JSON-compatible finding object with ruleId, message, file, line, severity, pillar, secondaryPillars, tier, confidence, remediation (empty
        string when absent), fingerprint, stableIdentity and metadata, plus endLine, column and symbol when they apply.
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
    """Project one run diagnostic into the machine diagnostic object.

    invalidatesRun defaults to true when the diagnostic leaves it unset. The file comes from file_path, falling back to path, and is omitted when it
    cannot be expressed under the project root; line appears only when positive.

    Args:
        diagnostic: Run diagnostic to project.
        root: Project root used to make the diagnostic's file path relative.

    Returns:
        JSON-compatible diagnostic object with type, message, invalidatesRun and, when available, file and line.
    """
    payload: dict[str, Any] = {
        "type": diagnostic.type,
        "message": diagnostic.message,
        "invalidatesRun": (True if diagnostic.invalidates_run is None else diagnostic.invalidates_run),
    }
    source_path = diagnostic.file_path or diagnostic.path
    if source_path:
        file_path = _machine_relative_path(source_path, root)
        if file_path is not None:
            payload["file"] = file_path
    if diagnostic.line is not None and diagnostic.line > 0:
        payload["line"] = diagnostic.line
    return payload


def _machine_ignored_paths(
    report: AnalysisReport,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build the sorted ignored-path details and the ignored path list, and require both to name the same paths in the same order.

    Details are sorted by path while the ignored path list keeps the report's order after de-duplication, so the report's ignored paths must already
    be in sorted order and match the details one for one.

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

    Paths are made root-relative and de-duplicated. symbol appears only when set, and source whenever the row names one: built-in on a test-path skip
    row, inline or duplicate on a section 13c row; a configured row carries none.

    Args:
        summary: Suppression summary row to project.
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
    # Only a built-in row names its source; a configured row is recognised by carrying none.
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
    """Project a baseline report into the machine baseline section.

    applied is false when this run generated the baseline rather than comparing against one. newFindings combines the new, collision and not-eligible
    counts, and path appears only when it can be expressed under the project root.

    Args:
        value: Baseline extension value from the report; anything other than a BaselineReport means there is no baseline section.
        root: Project root used to make the baseline file path relative.

    Returns:
        JSON-compatible baseline object, or None when value is not a BaselineReport.
    """
    if not isinstance(value, BaselineReport):
        return None
    payload: dict[str, Any] = {
        "applied": not value.generated,
        "entries": value.total_entries,
        "generated": value.generated,
        "newFindings": value.new_count + value.collision_count + value.not_eligible_count,
        "resolvedFindings": value.absent_count,
        "source": value.source,
        "stale": [_machine_baseline_entry(item) for item in value.stale_entries],
        "staleEntries": len(value.stale_entries),
        "staleEvaluation": value.stale_evaluation,
        "suppressedFindings": value.suppressed_findings,
        "unchangedFindings": value.unchanged_count,
    }
    path = _machine_relative_path(value.path, root)
    if path is not None:
        payload["path"] = path
    return payload


def _machine_baseline_entry(value: Any) -> dict[str, Any]:
    """Render one resolved row: the identity, how many occurrences went away, and the descriptive fields it carried.

    Args:
        value: Stale baseline entry from the baseline report, carrying an identity, a count and optional rule, path and subject.

    Returns:
        JSON-compatible object with identity and count, plus ruleId, path and subject only when non-empty.
    """
    payload: dict[str, Any] = {"identity": value.identity, "count": value.count}
    # A row's rule, path, and subject exist for the reader, so an absent one is omitted rather than written empty.
    for key, text in (("ruleId", value.rule_id), ("path", value.path), ("subject", value.subject)):
        if text:
            payload[key] = text
    return payload


def _machine_diff(value: Any, root: str) -> dict[str, Any] | None:
    """Project the diff extension into the machine diff section when diff mode was enabled.

    The native value is converted through its to_dict when it has one. filteredFindings is the native suppressedCount, mode comes from the native
    source and appears only when it is a non-empty string, and caveat appears only when it is a string.

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
    """Convert a native extension value to its dictionary form when it provides to_dict.

    Args:
        value: Native extension value or plain data.

    Returns:
        The result of value.to_dict() when value has a callable to_dict, otherwise value unchanged.
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
    """Make requested input paths root-relative and de-duplicate them, dropping any input that has no form under the project root.

    Args:
        values: Requested input paths, each converted with str before projection.
        root: Project root, or the launch directory when the run never resolved one.

    Returns:
        Root-relative POSIX input paths without duplicates, in first-seen order, with inputs outside the root omitted.
    """
    # A run that could not start never resolved a project root, so its envelope is rooted at the launch directory,
    # and a target named from a sibling directory, such as `analyse ../proj`, has no form under it. A host path may
    # not be published, so the input is left out the way the config path beside it already is, instead of raising
    # and losing the one envelope that says why the run could not start.
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        path = _machine_relative_path(str(value), root)
        if path is not None and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _machine_path(value: str, root: str) -> str:
    """Make one path root-relative, refusing any path that cannot be published under the project root.

    Args:
        value: Absolute path, or path relative to root, to project.
        root: Project root the path is made relative to.

    Returns:
        Root-relative POSIX path.

    Raises:
        ValueError: When _machine_relative_path finds no form for value under root, such as a path outside the root, an empty or backslash path, or a
            Windows drive path.
    """
    path = _machine_relative_path(value, root)
    if path is None:
        raise ValueError(f"machine path {value!r} is outside the project root")
    return path


def _machine_relative_path(value: str, root: str) -> str | None:
    """Express a path relative to the project root in POSIX form, or report that it has no publishable form.

    A relative value is resolved against root and symlinks are resolved on both sides. An OSError while resolving the candidate path counts as having
    no form; resolving root itself is not guarded.

    Args:
        value: Absolute path, or path relative to root, to project.
        root: Project root the result is relative to.

    Returns:
        Root-relative POSIX path, . for the root itself, or None when value is empty, contains a backslash, starts with a Windows drive letter,
        resolves outside root, or cannot be resolved.
    """
    if not value or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return None
    root_path = Path(root).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    try:
        relative = candidate.resolve().relative_to(root_path)
    except (OSError, ValueError):
        return None
    return relative.as_posix()
