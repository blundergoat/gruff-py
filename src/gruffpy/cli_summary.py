"""``gruff-py summary`` payload + text renderers (pillar rows, grouped rules, hints).

Carved out of ``src/gruffpy/cli.py`` to keep that file under the
``size.file-length`` 1000-line error threshold; mirrors the
``src/gruffpy/cli_dashboard.py`` / ``src/gruffpy/cli_list_rules.py`` carve-outs.
"""

from __future__ import annotations

import shlex
from collections import Counter
from typing import Any, cast

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.schema import SUMMARY_SCHEMA_VERSION
from gruffpy.version import TOOL_NAME


def summary_payload(
    report: AnalysisReport,
    top: int,
    elapsed_seconds: float,
    *,
    group_by: str = "none",
) -> dict[str, Any]:
    """Build the ``gruff.summary.v2`` payload for the summary command.

    Args:
        report: Analysis report to summarise.
        top: Row cap applied to ``topRules`` / ``topFiles`` / ``groupedRules``.
        elapsed_seconds: Wall-clock duration of the underlying analyse run.
        group_by: ``"rule"`` to add the ``groupedRules`` block; anything else
            leaves the default shape intact.

    Returns:
        JSON-ready dict matching the ``gruff.summary.v2`` schema.
    """
    rule_counts = Counter(finding.rule_id for finding in report.findings)
    file_counts = Counter(finding.file_path for finding in report.findings)
    payload: dict[str, Any] = {
        "schemaVersion": SUMMARY_SCHEMA_VERSION,
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

    Args:
        report: Analysis report to summarise.
        top: Row cap applied to ``topRules`` / ``topFiles`` / ``groupedRules``.
        elapsed_seconds: Wall-clock duration of the underlying analyse run.
        group_by: ``"rule"`` to render the ``Grouped by rule`` block in place
            of the default ``Top rules`` block.

    Returns:
        Multi-line text payload ending in a single trailing newline.
    """
    payload = summary_payload(report, top, elapsed_seconds, group_by=group_by)
    summary = payload["summary"]
    counts = report.finding_counts()
    paths_display = ", ".join(summary["paths"]) if summary["paths"] else "(none)"
    lines = [
        f"{TOOL_NAME} {report.tool_version} summary",
        f"Path: {paths_display}",
        (
            f"Files: {summary['filesDiscovered']} discovered, {summary['filesParsed']} parsed, "
            f"{summary['ignored']} ignored, {summary['missing']} missing, "
            f"{summary['parseErrors']} parse errors"
        ),
    ]
    if report.score is not None:
        lines.append(
            f"Composite: {report.score.composite.letter} "
            f"({report.score.composite.score:.2f} / 100)"
        )
    lines.append(
        f"Findings: {counts['total']} total · {counts['error']} error · "
        f"{counts['warning']} warning · {counts['advisory']} advisory"
    )
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
    _append_summary_hints(lines, summary)
    return "\n".join(lines) + "\n"


def _format_grouped_rule_rows(grouped: dict[str, Any]) -> list[str]:
    rows = cast(list[dict[str, Any]], grouped["rows"])
    shown = cast(int, grouped["shown"])
    total = cast(int, grouped["total"])
    header = f"Grouped by rule (showing {shown} of {total}):"
    if not rows:
        return [header, "  none"]
    rule_id_width = max(len(row["ruleId"]) for row in rows)
    formatted = [header]
    for row in rows:
        line = (
            f"  {row['count']:>4}  "
            f"{row['ruleId']:<{rule_id_width}}  "
            f"{row['severity']:<8}  "
            f"{row['confidence']}"
        )
        formatted.append(line.rstrip())
    return formatted


def _summary_pillar_rows(report: AnalysisReport) -> list[dict[str, Any]]:
    """Build the canonical per-pillar summary rows sorted by findings DESC, pillar ASC.

    Sources grade/score/per-severity data from the ``ScoreReport`` attached to
    *report* when available; falls back to per-finding counts otherwise.
    Only applicable pillars appear in the returned list.

    Args:
        report: Analysis report to summarise.

    Returns:
        List of pillar dicts shaped per ``gruff.summary.v2``.
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
    hints: list[str] = []
    if summary["ignored"]:
        hints.append(
            "Ignored paths: add --include-ignored to include built-in and .gitignore "
            "exclusions; configured paths.ignore still applies."
        )
    if summary["findings"]:
        hints.append(
            "Baseline: after review, run "
            f"`{_generate_baseline_command(cast(list[str], summary['paths']))}` "
            "to accept current findings as known debt."
        )
    if not hints:
        return
    lines.extend(["", "Next steps:"])
    lines.extend(f"  {hint}" for hint in hints)


def _generate_baseline_command(paths: list[str]) -> str:
    command_paths = paths or ["."]
    joined_paths = " ".join(shlex.quote(path) for path in command_paths)
    return f"{TOOL_NAME} analyse {joined_paths} --generate-baseline --fail-on none"


def _counter_rows(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in counter.most_common(top)]


def _format_count_rows(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["  none"]
    return [f"  {row['name']}: {row['count']}" for row in rows]
