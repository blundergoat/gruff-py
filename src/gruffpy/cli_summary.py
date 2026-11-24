"""Render terminal and JSON output for the `gruff-py summary` command.

Use this module when a developer runs `gruff-py summary` for a compact repository health check without printing every individual finding.
It keeps the terminal masthead, pillar grades, top/grouped rules, diagnostics, and baseline hints aligned with `FAMILY-CONTRACT.md`.

- `summary_payload`: returns the canonical findings-free `gruff.summary.v3` JSON envelope.
- `summary_text`: formats the human-readable terminal summary, including `--group-by rule` severity breakdowns.
"""

from __future__ import annotations

import shlex
from collections import Counter
from typing import Any, cast

from gruffpy.analysis.report import AnalysisReport
from gruffpy.reporting.text_reporter import append_sensitive_exclusions
from gruffpy.version import TOOL_NAME


def summary_payload(
    report: AnalysisReport,
    top: int,
    elapsed_seconds: float,
    *,
    group_by: str = "none",
) -> dict[str, Any]:
    """Return the exact gruff.summary.v3 projection for the summary command.

    Args:
        report: Analysis report to summarise.
        top: Text-only row cap retained in the shared command signature.
        elapsed_seconds: Text-only elapsed time retained in the shared command signature.
        group_by: Text-only grouping mode retained in the shared command signature.

    Returns:
        Canonical analysis payload without findings and with schemaVersion set to gruff.summary.v3.
    """
    del top, elapsed_seconds, group_by
    return report.to_summary_dict()


def _text_summary_payload(
    report: AnalysisReport,
    top: int,
    elapsed_seconds: float,
    *,
    group_by: str,
) -> dict[str, Any]:
    """Build the native aggregate data used only by the human text renderer.

    Args:
        report: Completed scan supplying findings, path counts, diagnostics and pillar results.
        top: Row cap passed to counter ranking and grouped-rule slicing.
        elapsed_seconds: Scan duration rounded to three decimals in the summary fields.
        group_by: The value "rule" adds grouped-rule rows; other values leave that field absent.

    Returns:
        Text-view summary fields, pillar rows, ranked rule/file counts and diagnostic payloads.
    """
    rule_counts = Counter(finding.rule_id for finding in report.findings)
    file_counts = Counter(finding.file_path for finding in report.findings)
    payload: dict[str, Any] = {
        "summary": {
            "paths": list(report.requested_paths),
            "filesDiscovered": report.files_discovered,
            "filesParsed": report.files_parsed,
            "ignored": len(report.ignored_paths),
            "missing": len(report.missing_paths),
            "parseErrors": report.parse_error_count(),
            "findings": len(report.findings),
            "exitCode": report.exit_code,
            "elapsedSeconds": round(elapsed_seconds, 3),
        },
        "pillars": _summary_pillar_rows(report),
        "topRules": _counter_rows(rule_counts, top),
        "topFiles": _counter_rows(file_counts, top),
        "diagnostics": [diagnostic.to_dict() for diagnostic in report.diagnostics],
    }
    if group_by == "rule":
        rule_rows = report.finding_counts_by_rule()
        payload["groupedRules"] = {
            "shown": min(top, len(rule_rows)),
            "total": len(rule_rows),
            "rows": rule_rows[:top],
        }
    return payload


def summary_text(
    report: AnalysisReport,
    top: int,
    elapsed_seconds: float,
    *,
    group_by: str = "none",
) -> str:
    """Render the summary command's text output.

    FAMILY-CONTRACT.md requires the audit of sensitive exclusions here because those exclusions filter this command's findings.

    Args:
        report: Completed scan supplying the score, finding counts, diagnostics and sensitive-exclusion audit.
        top: Row cap for the top rules, top files and grouped rule counts.
        elapsed_seconds: Wall-clock duration of the underlying analyse run.
        group_by: The value "rule" replaces the default Top rules block with Grouped by rule.

    Returns:
        Multiline summary text with a newline appended after the rendered lines.
    """
    payload = _text_summary_payload(report, top, elapsed_seconds, group_by=group_by)
    summary = payload["summary"]
    counts = report.finding_counts()
    paths_display = ", ".join(summary["paths"]) if summary["paths"] else "(none)"
    # FAMILY-CONTRACT section 1 fixes the masthead and two-line composite block above the scan details.
    # The grade stays in the same position in summary and analyse so readers can find it in either view.
    composite = None if report.score is None else report.score.composite
    lines = [
        f"{TOOL_NAME} {report.tool_version} summary",
        ("Composite: n/a (nothing evaluated)" if composite is None else f"Composite: {composite.letter} ({composite.score:.2f} / 100)"),
        f"Findings: {counts['total']} total · {counts['error']} error · {counts['warning']} warning · {counts['advisory']} advisory",
        f"Path: {paths_display}",
        (
            f"Files: {summary['filesDiscovered']} discovered, {summary['filesParsed']} parsed, "
            f"{summary['ignored']} ignored, {summary['missing']} missing, "
            f"{summary['parseErrors']} parse errors"
        ),
    ]
    lines.extend(
        [
            f"Elapsed: {summary['elapsedSeconds']:.3f}s",
            "",
            "Pillars",
        ]
    )
    lines.extend(_format_pillar_text_rows(cast(list[dict[str, Any]], payload["pillars"])))
    if group_by == "rule":
        lines.append("")
        lines.extend(_format_grouped_rule_rows(cast(dict[str, Any], payload["groupedRules"])))
    else:
        lines.extend(["", "Top rules:"])
        lines.extend(_format_count_rows(cast(list[dict[str, Any]], payload["topRules"])))
    lines.extend(["", "Top files:"])
    lines.extend(_format_count_rows(cast(list[dict[str, Any]], payload["topFiles"])))
    if report.diagnostics:
        lines.extend(["", "Diagnostics"])
        for diagnostic in report.diagnostics:
            location = diagnostic.file_path or diagnostic.path
            if diagnostic.file_path is not None and diagnostic.line is not None:
                location = f"{diagnostic.file_path}:{diagnostic.line}"
            suffix = "" if location is None else f" {location}"
            lines.append(f"  [{diagnostic.type.upper()}]{suffix} {diagnostic.message}")
    append_sensitive_exclusions(lines, report)
    _append_summary_hints(lines, summary)
    return "\n".join(lines) + "\n"


def _format_grouped_rule_rows(grouped: dict[str, Any]) -> list[str]:
    """Format aligned terminal rows for `gruff-py summary --group-by rule` showing count, rule ID, severity, and confidence.

    Args:
        grouped: Grouping dictionary containing `rows`, `shown`, and `total` counts for the section heading.

    Returns:
        Section heading plus aligned rule rows, or the heading followed by `  none` when the scan produced no findings.
    """
    rows = cast(list[dict[str, Any]], grouped["rows"])
    shown = cast(int, grouped["shown"])
    total = cast(int, grouped["total"])
    header = f"Grouped by rule (showing {shown} of {total}):"
    # Print an explicit empty-state marker so a clean scan clearly shows zero grouped rules.
    if not rows:
        return [header, "  none"]
    rule_id_width = max(len(row["ruleId"]) for row in rows)
    severity_labels = [_grouped_severity_label(row) for row in rows]
    severity_width = max(8, max(len(label) for label in severity_labels))
    formatted = [header]
    # Align columns across all displayed rules so developers can scan counts and mixed severities vertically.
    for row, severity_label in zip(rows, severity_labels, strict=True):
        line = f"  {row['count']:>4}  {row['ruleId']:<{rule_id_width}}  {severity_label:<{severity_width}}  {row['confidence']}"
        formatted.append(line.rstrip())
    return formatted


def _grouped_severity_label(row: dict[str, Any]) -> str:
    """Format one grouped-rule severity cell, showing a per-severity breakdown when a rule emits mixed severities.

    For example, when `docs.missing-function-docstring` emits 7 warning production findings and 11 advisory test findings,
    this returns `7 warning, 11 advisory` so the developer sees both buckets instead of only the worst severity.

    Args:
        row: Grouped rule entry carrying worst `severity` and optional `severityCounts` mapping.

    Returns:
        Single severity label when all findings share one severity, or a comma-separated `error`/`warning`/`advisory` breakdown when mixed.
    """
    counts = row.get("severityCounts")
    # Expand the cell into explicit severity counts only when findings span two or more severity levels.
    if isinstance(counts, dict):
        parts = [f"{counts[level]} {level}" for level in ("error", "warning", "advisory") if counts.get(level, 0) > 0]
        # Keep single-severity rules compact (for example `warning`), while mixed rules show exact counts per level.
        if len(parts) > 1:
            return ", ".join(parts)
    return str(row["severity"])


def _summary_pillar_rows(report: AnalysisReport) -> list[dict[str, Any]]:
    """Build applicable pillar rows ordered by descending finding count, then pillar name.

    Use attached score data or fall back to per-finding counts; unavailable grades and scores are None.

    Args:
        report: Analysis report to summarise.

    Returns:
        List of native pillar dicts used by the text summary.
    """
    rows: list[dict[str, Any]] = []
    if report.score is None:
        pillar_counts = Counter(finding.pillar.value for finding in report.findings)
        severity_counts: dict[str, Counter[str]] = {name: Counter() for name in pillar_counts}
        for finding in report.findings:
            severity_counts[finding.pillar.value][finding.severity.value] += 1
        rows.extend(
            {
                "pillar": name,
                "grade": None,
                "score": None,
                "applicable": True,
                "findings": count,
                "advisory": severity_counts[name].get("advisory", 0),
                "warning": severity_counts[name].get("warning", 0),
                "error": severity_counts[name].get("error", 0),
                "penalty": 0.0,
            }
            for name, count in pillar_counts.items()
        )
    else:
        rows.extend(
            {
                "pillar": pillar.pillar,
                "grade": pillar.grade.letter if pillar.grade is not None else None,
                "score": pillar.grade.score if pillar.grade is not None else None,
                "applicable": pillar.applicable,
                "findings": pillar.findings,
                "advisory": pillar.advisories,
                "warning": pillar.warnings,
                "error": pillar.errors,
                "penalty": pillar.penalty,
            }
            for pillar in report.score.pillars
            if pillar.applicable
        )
    rows.sort(key=lambda row: (-cast(int, row["findings"]), cast(str, row["pillar"])))
    return rows


def _format_pillar_text_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Present pillar grades and per-severity counts in aligned terminal rows.

    Args:
        rows: Native pillar summaries in display order; grade and score may be absent as None.

    Returns:
        Aligned rows with placeholders for absent grades/scores, or one none marker for an empty input.
    """
    if not rows:
        return ["  none"]
    pillar_width = max(15, max(len(cast(str, row["pillar"])) for row in rows))
    lines: list[str] = []
    for row in rows:
        grade = cast(str | None, row["grade"])
        score = cast(float | None, row["score"])
        grade_text = grade if grade is not None else "-"
        score_text = f"{score:6.2f}" if score is not None else "  n/a "
        lines.append(
            "  "
            + cast(str, row["pillar"]).ljust(pillar_width)
            + " "
            + grade_text
            + " "
            + score_text
            + " "
            + f"findings={row['findings']}".ljust(15)
            + f"advisory={row['advisory']}".ljust(15)
            + f"warning={row['warning']}".ljust(14)
            + f"error={row['error']}"
        )
    return lines


def _append_summary_hints(lines: list[str], summary: dict[str, Any]) -> None:
    """Append next-step guidance when a text summary has ignored paths or findings.

    Args:
        lines: Rendered summary lines to extend in place; unchanged when neither hint applies.
        summary: Aggregate fields whose ignored/findings counts select hints and whose paths build the baseline command.

    Returns:
        None; applicable hints are appended to lines in place.
    """
    hints: list[str] = []
    if summary["ignored"]:
        hints.append("Ignored paths: add --include-ignored to include built-in and .gitignore exclusions; configured paths.ignore still applies.")
    if summary["findings"]:
        hints.append(
            f"Baseline: after review, run `{_generate_baseline_command(cast(list[str], summary['paths']))}` to accept current findings as known debt."
        )
    if not hints:
        return
    lines.extend(["", "Next steps:"])
    lines.extend(f"  {hint}" for hint in hints)


def _generate_baseline_command(paths: list[str]) -> str:
    """Build a shell-quoted command for accepting the displayed scan as a baseline.

    Args:
        paths: Scan operands to preserve; an empty list substitutes the current-directory operand.

    Returns:
        An analyse command with each operand quoted and baseline generation set not to fail on findings.
    """
    command_paths = paths or ["."]
    joined_paths = " ".join(shlex.quote(path) for path in command_paths)
    return f"{TOOL_NAME} analyse {joined_paths} --generate-baseline --fail-on none"


def _counter_rows(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    """Select the most frequent rule or file names for the text-summary ranking.

    Args:
        counter: Name-to-count totals to rank with Counter's ordering.
        top: Maximum number of rows; zero or a negative value yields no rows.

    Returns:
        Name/count dictionaries for the selected entries in descending-frequency order.
    """
    return [{"name": name, "count": count} for name, count in counter.most_common(top)]


def _format_count_rows(rows: list[dict[str, Any]]) -> list[str]:
    """Render ranked name/count entries beneath an existing summary heading.

    Args:
        rows: Ranked entries with name and count fields, in their intended display order.

    Returns:
        Indented name/count lines, or one explicit none marker when no entries were selected.
    """
    if not rows:
        return ["  none"]
    return [f"  {row['name']}: {row['count']}" for row in rows]
