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
    "build": "build-output",
    "coverage": "build-output",
    "dist": "build-output",
    "htmlcov": "build-output",
    "node_modules": "dependency",
    "vendor": "dependency",
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
    root = report.machine_context.project_root
    payload: dict[str, Any] = {
        "failOn": report.fail_on,
        "format": report.format,
        "inputs": _machine_paths(report.requested_paths, root),
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
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _machine_summary(
    report: AnalysisReport,
    findings: tuple[Finding, ...],
    details: list[dict[str, Any]],
) -> dict[str, Any]:
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
    counts = {"advisory": 0, "warning": 0, "error": 0, "total": len(findings)}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _finding_counts_by_pillar(findings: tuple[Finding, ...]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.pillar.value] = counts.get(finding.pillar.value, 0) + 1
    return dict(sorted(counts.items()))


def _machine_finding(finding: Finding, root: str) -> dict[str, Any]:
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
    root = report.machine_context.project_root
    details = [_machine_path_detail(item, root) for item in report.ignored_path_details]
    details.sort(key=lambda item: item["path"])
    ignored_paths = _machine_paths(report.ignored_paths, root)
    detail_paths = [str(item["path"]) for item in details]
    if ignored_paths != detail_paths:
        raise ValueError("ignored paths and their machine details must have identical paths")
    return details, ignored_paths


def _machine_path_detail(detail: IgnoredPath, root: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "path": _machine_path(detail.path, root),
        "reason": _skip_reason(detail),
        "source": detail.source,
    }
    if detail.pattern:
        payload["pattern"] = detail.pattern
    return payload


def _skip_reason(detail: IgnoredPath) -> str:
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
    payload: dict[str, Any] = {
        "index": summary.index,
        "rule": summary.rule,
        "paths": _machine_paths(summary.paths, root),
        "reason": summary.reason,
        "suppressed": summary.suppressed,
    }
    if summary.symbol:
        payload["symbol"] = summary.symbol
    return payload


def _machine_score(score: ScoreReport | None, root: str) -> dict[str, Any]:
    if score is None:
        return {
            "composite": {"grade": "N/A", "score": 0.0},
            "pillars": [],
            "topOffenders": [],
            "coverage": {
                "contributingPillars": [],
                "caveat": "No score was produced for this run.",
            },
        }
    return {
        "composite": {
            "grade": score.composite.letter,
            "score": score.composite.score,
        },
        "pillars": [_machine_pillar_score(item) for item in score.pillars],
        "topOffenders": [_machine_file_score(item, root) for item in score.top_offenders],
        "complexityDistribution": dict(score.complexity_distribution),
        "scope": score.scope,
        "explanation": score.explanation,
    }


def _machine_pillar_score(score: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "pillar": score.pillar,
        "findings": score.findings,
        "penalty": round(score.penalty, 2),
        "advisory": score.advisories,
        "warning": score.warnings,
        "error": score.errors,
        "applicable": score.applicable,
    }
    if score.grade is not None:
        payload["grade"] = score.grade.letter
        payload["score"] = score.grade.score
    return payload


def _machine_file_score(score: Any, root: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "file": _machine_path(score.file_path, root),
        "findings": score.findings,
        "advisory": score.advisories,
        "warning": score.warnings,
        "error": score.errors,
        "grade": score.grade.letter,
        "score": score.grade.score,
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
    if not isinstance(value, BaselineReport):
        return None
    payload: dict[str, Any] = {
        "applied": not value.generated,
        "entries": value.total_entries,
        "generated": value.generated,
        "source": value.source,
        "stale": [_machine_baseline_entry(item, root) for item in value.stale_entries],
        "staleEntries": len(value.stale_entries),
        "staleEvaluation": value.stale_evaluation,
        "suppressedFindings": value.suppressed_findings,
    }
    path = _machine_relative_path(value.path, root)
    if path is not None:
        payload["path"] = path
    return payload


def _machine_baseline_entry(value: Any, root: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "fingerprint": value.fingerprint,
        "ruleId": value.rule_id,
        "file": _machine_path(value.file_path, root),
        "message": value.message,
    }
    if value.line is not None:
        payload["line"] = value.line
    if value.symbol:
        payload["symbol"] = value.symbol
    return payload


def _machine_diff(value: Any, root: str) -> dict[str, Any] | None:
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
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value


def _machine_paths(values: Any, root: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for value in values:
        path = _machine_path(str(value), root)
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _machine_path(value: str, root: str) -> str:
    path = _machine_relative_path(value, root)
    if path is None:
        raise ValueError(f"machine path {value!r} is outside the project root")
    return path


def _machine_relative_path(value: str, root: str) -> str | None:
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
