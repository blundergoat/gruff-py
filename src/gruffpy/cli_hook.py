"""Click command for the ``gruff.hook.v2`` agent-hook contract.

The ``hook`` subcommand lives in its own module so its CLI wiring sits next to
the projection logic in :mod:`gruffpy.hook_contract` without growing
:mod:`gruffpy.cli`. It is registered on the root group from :mod:`gruffpy.cli`.
"""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import click

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineError, BaselineOptions, apply_baseline
from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.runner import run_analysis
from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.severity import Severity
from gruffpy.hook_contract import (
    capabilities_payload,
    config_error_payload,
    fatal_payload,
    hook_payload,
    render_json,
    stable_identities_from_git_base,
)
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter

_SEVERITY_RANK = {Severity.ADVISORY: 0, Severity.WARNING: 1, Severity.ERROR: 2}

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _apply_hook_decorators(command: Callable[..., Any]) -> Callable[..., Any]:
    """Attach the hook CLI options so the callback can receive the parsed invocation as keyword arguments.

    Args:
        command: The Click callback the options decorate.

    Returns:
        The callback with the hook options attached in reverse declaration order.
    """
    for decorator in reversed(_HOOK_COMMAND_DECORATORS):
        command = decorator(command)
    return command


@dataclass(frozen=True, slots=True)
class _ExitGate:
    """What the caller asked the hook to block on.

    Severity and confidence are independent floors, so a finding blocks only by
    clearing both. The baseline dimension sits beside them: an unreviewed
    finding blocks whatever its severity, because it is what the edit added.

    Attributes:
        fail_on: Lowest severity that exits 1; ``none`` means no severity does.
        min_confidence: Lowest confidence that reaches the gate.
        fail_on_new: Whether a finding the baseline calls new blocks on its own.
        fail_on_diagnostics: Whether any diagnostic at all blocks.
    """

    fail_on: str
    min_confidence: str
    fail_on_new: bool
    fail_on_diagnostics: bool


_HOOK_COMMAND_DECORATORS: tuple[Callable[[Callable[..., Any]], Callable[..., Any]], ...] = (
    # The flag stays accepted and Choice-validated; the callback never used its value.
    click.option(
        "--format",
        "hook_format",
        type=click.Choice(["json"]),
        default="json",
        expose_value=False,
    ),
    click.option("--capabilities", is_flag=True, default=False, help="Emit hook capabilities JSON."),
    click.option(
        "--changed-ranges",
        type=str,
        default=None,
        help='Explicit changed line ranges such as "3-3,8-10".',
    ),
    click.option("--diff", "diff_ref", default="", help="Git ref for hook new-only comparison."),
    click.option(
        "--baseline",
        "hook_baseline_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Hook or analysis JSON file for stableIdentity new-only comparison.",
    ),
    click.option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file.",
    ),
    click.option("--no-config", is_flag=True, default=False, help="Skip config loading."),
    click.option(
        "--deep-scan-budget",
        default="",
        help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
    ),
    click.option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; config ignores still apply.",
    ),
    click.option(
        "--exclude-rule",
        multiple=True,
        help="Execution-level rule IDs to skip; accepts comma-separated or repeated values.",
    ),
    click.option(
        "--fail-on",
        "fail_on",
        type=click.Choice(["none", "advisory", "warning", "error"]),
        default="none",
        help="Lowest severity that exits 1. The hook default of none keeps findings advisory.",
    ),
    click.option(
        "--min-confidence",
        "min_confidence",
        type=click.Choice(["low", "medium", "high"]),
        default="low",
        help="Lowest confidence that reaches the exit gate, independent of severity.",
    ),
    click.option(
        "--fail-on-new",
        is_flag=True,
        default=False,
        help="Exit 1 when any published finding is new against the applied baseline.",
    ),
    click.option(
        "--fail-on-diagnostics",
        is_flag=True,
        default=False,
        help="Exit 1 when the run reports any diagnostic, however minor.",
    ),
    click.argument("paths", nargs=-1),
)


@click.command("hook", help="Run gruff-py analysis for an agent hook.")
@_apply_hook_decorators
# gruff: disable-next=docs.missing-param-doc -- option help= text documents each flag.
def hook(**kwargs: Any) -> None:
    """Serve the gruff.hook.v2 capabilities probe or execute an agent-hook analysis.

    Args:
        kwargs: Click-parsed hook options and paths; capabilities selects the feature probe.

    Returns:
        No normal return; capabilities and analysis finish through SystemExit.

    Raises:
        SystemExit: With zero for capabilities, otherwise the analysis or validation status.
    """
    # Lazy import avoids a cli <-> cli_hook import cycle at module load.
    from gruffpy.cli import _write_stdout

    # A probe wants the feature list and nothing else, so it is answered before any run is described.
    if bool(kwargs["capabilities"]):
        _write_stdout(render_json(capabilities_payload()))
        sys.exit(0)

    _execute_hook(
        changed_ranges=cast("str | None", kwargs["changed_ranges"]),
        diff_ref=str(kwargs["diff_ref"]),
        hook_baseline_path=kwargs["hook_baseline_path"],
        config_path=kwargs["config_path"],
        no_config=bool(kwargs["no_config"]),
        deep_scan_budget=str(kwargs["deep_scan_budget"]),
        include_ignored=bool(kwargs["include_ignored"]),
        exclude_rule=tuple(kwargs["exclude_rule"]),
        gate=_ExitGate(
            fail_on=str(kwargs["fail_on"]),
            min_confidence=str(kwargs["min_confidence"]),
            fail_on_new=bool(kwargs["fail_on_new"]),
            fail_on_diagnostics=bool(kwargs["fail_on_diagnostics"]),
        ),
        paths=tuple(kwargs["paths"]),
    )


def _execute_hook(
    *,
    changed_ranges: str | None,
    diff_ref: str,
    hook_baseline_path: Path | None,
    config_path: Path | None,
    no_config: bool,
    deep_scan_budget: str,
    include_ignored: bool,
    exclude_rule: tuple[str, ...],
    gate: _ExitGate,
    paths: tuple[str, ...],
) -> None:
    """Run one hook invocation and exit, so the decorated command stays a thin entry point.

    Args:
        changed_ranges: Explicit changed line ranges such as 3-3,8-10; None omits this filter.
            An empty string is refused instead of widening the scan.
        diff_ref: Git ref for new-only comparison; empty when no ``--diff`` was given.
        hook_baseline_path: Ratified baseline v3 file to apply. None skips file-based baseline matching.
        config_path: Explicit config file, or None to discover the project default.
        no_config: Whether config discovery is disabled.
        include_ignored: Include default-ignored and gitignored paths in discovery while keeping configured ignores in effect.
        deep_scan_budget: Raw budget override from --deep-scan-budget. Empty uses the configured bounds.
        exclude_rule: Execution-level rule ids to skip, comma-separated or repeated.
        gate: What the caller asked the hook to block on.
        paths: Requested hook paths; empty means the current directory.

    Returns:
        Does not return. Sends hook JSON to stdout unless quiet or silent mode suppresses output, then exits with SystemExit.
        Conflicting baseline and diff flags produce a stderr error without JSON.

    Raises:
        SystemExit: Exit code 2 for conflicting baseline and diff flags or a caught ConfigError, BaselineError or ValueError.
            Otherwise uses the gate-selected exit code.
    """
    # Lazy import avoids a cli <-> cli_hook import cycle at module load.
    from gruffpy.cli import _write_stdout

    if hook_baseline_path is not None and diff_ref:
        click.echo("--baseline and --diff cannot be combined in hook mode.", err=True)
        sys.exit(2)

    try:
        base_identities = _hook_base_identities(
            paths=paths,
            diff_ref=diff_ref,
            config_path=config_path,
            no_config=no_config,
            include_ignored=include_ignored,
            deep_scan_budget=deep_scan_budget,
        )
        report = _run_hook_analysis(
            paths=paths,
            config_path=config_path,
            no_config=no_config,
            include_ignored=include_ignored,
            exclude_rule=exclude_rule,
            deep_scan_budget=deep_scan_budget,
        )
        gated, statuses = _apply_hook_baseline(_findings_before_display_filtering(report), hook_baseline_path)
        # Build the payload inside the try: a malformed --changed-ranges value
        # raises ValueError here, which must surface as a controlled exit 2 rather
        # than an uncaught traceback that breaks the stable hook contract.
        payload = hook_payload(
            _report_with(report, gated),
            paths=paths or (".",),
            changed_ranges=changed_ranges,
            base_stable_identities=base_identities,
            mode=_run_mode(changed_ranges, diff_ref),
            baseline_path=str(hook_baseline_path) if hook_baseline_path is not None else None,
            baseline_statuses=statuses,
            suppressions=report.suppressions,
        )
    except ConfigError as exc:
        _write_stdout(render_json(config_error_payload(exc)))
        sys.exit(2)
    except BaselineError as exc:
        # An unreadable or incompatible baseline makes the hook report a fatal error before any findings are published.
        _write_stdout(render_json(fatal_payload("baseline", str(exc))))
        click.echo(str(exc), err=True)
        sys.exit(2)
    except ValueError as exc:
        _write_stdout(render_json(fatal_payload("changed-region", str(exc))))
        click.echo(str(exc), err=True)
        sys.exit(2)

    _write_stdout(render_json(payload))
    sys.exit(_hook_exit_code(payload, gate))


def _findings_before_display_filtering(report: AnalysisReport) -> tuple[Finding, ...]:
    """Select the findings available to the hook before display filtering.

    A minimumSeverity display floor controls what readers see while the hook still gates on the findings available before presentation.

    Args:
        report: Run report holding the displayed findings and any saved pre-display findings.

    Returns:
        The pre-display findings if nonempty, otherwise the report's displayed findings.
    """
    return report.machine_context.summary_findings or report.findings


def _report_with(report: AnalysisReport, findings: tuple[Finding, ...]) -> AnalysisReport:
    """Return the report with its findings replaced, leaving every other field alone.

    Args:
        report: The analysis report the run produced.
        findings: Replacement findings for hook output, including all findings when no baseline was supplied.

    Returns:
        A copy carrying the gated findings.
    """
    return replace(report, findings=findings)


def _run_mode(changed_ranges: str | None, diff_ref: str) -> str:
    """Label the hook run audit so consumers can identify its filtering mode.

    Args:
        changed_ranges: Raw --changed-ranges text, None when unset.
        diff_ref: Raw --diff ref, empty when unset.

    Returns:
        changed-ranges for explicit ranges, diff for a Git comparison without explicit ranges, or full when neither was requested.
    """
    # When both selectors are supplied, the run audit names the explicit ranges.
    if changed_ranges is not None:
        return "changed-ranges"
    return "diff" if diff_ref else "full"


def _apply_hook_baseline(
    findings: tuple[Finding, ...],
    baseline_path: Path | None,
) -> tuple[tuple[Finding, ...], dict[int, str]]:
    """Apply a ``--baseline`` file, classifying every finding it covers.

    The hook applies the v3 baseline written by analyse --generate-baseline and refuses incompatible schemas or language ports.

    Args:
        findings: Findings this run produced.
        baseline_path: File the caller named, or None when they named none.

    Returns:
        The gated findings and the baseline status per finding, keyed by ``id``.

    Raises:
        BaselineError: When the file is missing, malformed, in another schema, or
            written by another port.
    """
    # With no baseline named, every finding stands and none carries a status a consumer could misread as reviewed.
    if baseline_path is None:
        return findings, {}

    result = apply_baseline(
        project_root=Path.cwd(),
        path=baseline_path,
        findings=findings,
        source="explicit",
    )
    gated = tuple(result.findings)
    reviewed = {id(finding) for finding in gated}
    statuses = {id(finding): "new" for finding in gated}
    for finding in findings:
        # A finding the baseline kept back is one the user already reviewed, which is what unchanged means.
        if id(finding) not in reviewed:
            statuses[id(finding)] = "unchanged"
    return gated, statuses


def _hook_exit_code(payload: dict[str, object], gate: _ExitGate) -> int:
    """Decide what the hook tells the calling agent, from the findings it published.

    Findings removed by changed-region or baseline filtering cannot block; published diagnostics can block when their gate is enabled.

    Args:
        payload: The published hook report.
        gate: What the caller asked the hook to block on.

    Returns:
        1 when enabled diagnostics are present, the new-finding gate matches a finding, or a finding meets both configured floors.
        Otherwise 0.
    """
    diagnostics = payload.get("diagnostics")
    # With the diagnostics gate enabled, a published diagnostic can block the run on its own.
    if gate.fail_on_diagnostics and isinstance(diagnostics, list) and diagnostics:
        return 1

    rows = payload.get("findings")
    if not isinstance(rows, list):
        return 0

    severity_floor = _SEVERITY_RANK.get(Severity(gate.fail_on)) if gate.fail_on != "none" else None
    confidence_floor = _CONFIDENCE_RANK[Confidence(gate.min_confidence)]

    for row in rows:
        if not isinstance(row, dict):
            continue
        if gate.fail_on_new and row.get("baselineStatus") == "new":
            return 1
        if severity_floor is None:
            continue
        severity = _SEVERITY_RANK.get(Severity(str(row.get("severity"))), 0)
        confidence = _CONFIDENCE_RANK.get(Confidence(str(row.get("confidence"))), 2)
        if severity >= severity_floor and confidence >= confidence_floor:
            return 1

    return 0


def _split_repeated_csv(values: tuple[str, ...]) -> tuple[str, ...]:
    """Expand repeated comma-separated rule selections without duplicate entries.

    Args:
        values: Repeated CLI values, each of which may contain comma-separated rule IDs.

    Returns:
        Trimmed, nonempty selections in first-seen order; empty when no selection remains.
    """
    items: list[str] = []
    for value in values:
        for item in value.split(","):
            stripped = item.strip()
            if stripped:
                items.append(stripped)
    return tuple(dict.fromkeys(items))


def _run_hook_analysis(
    *,
    paths: tuple[str, ...],
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    exclude_rule: tuple[str, ...],
    deep_scan_budget: str,
) -> AnalysisReport:
    """Analyse the working tree for hook output with baseline matching disabled.

    Args:
        paths: Requested source paths; an empty tuple selects the current directory.
        config_path: Explicit configuration file, or None for discovery when configuration loading is enabled.
        no_config: Uses registry defaults when true. An explicit config_path with this flag records a config-error diagnostic.
        include_ignored: Whether default-ignored and Git-ignored paths enter discovery.
        exclude_rule: Repeated or comma-separated rule IDs to exclude before rule execution.
        deep_scan_budget: Raw deep-scan override; empty retains the configured bounds.

    Returns:
        The working-tree analysis report for subsequent hook filtering and projection.

    Raises:
        ConfigError: If the analysis configuration cannot be loaded or validated, or the deep-scan override is invalid.
        ValueError: If the parsed minimum Python version is below 3.11.
    """
    return run_analysis(
        AnalysisRunRequest(
            paths=paths,
            config_path=config_path,
            no_config=no_config,
            output=OutputFormat.JSON,
            fail_threshold=FailThreshold.NONE,
            include_ignored=include_ignored,
            project_root=Path.cwd(),
            display_filter=FindingDisplayFilter(),
            baseline=BaselineOptions(disabled=True),
            execution_exclude_rules=_split_repeated_csv(exclude_rule),
            deep_scan_budget=deep_scan_budget,
        )
    )


def _hook_base_identities(
    *,
    paths: tuple[str, ...],
    diff_ref: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    deep_scan_budget: str,
) -> Counter[str] | None:
    """Resolve hook base stable identities, with their occurrence counts, for a ``--diff`` run.

    Diff runs compare hook identities from the Git base; baseline runs use the separate v3 baseline-matching path.

    Args:
        paths: Requested paths to read from the base tree; empty selects its whole tree.
        diff_ref: Git base ref, with working-tree meaning HEAD; empty disables the comparison.
        config_path: Explicit configuration file, or None to discover the working-tree default.
        no_config: Whether automatic configuration discovery is disabled.
        include_ignored: Whether default-ignored and Git-ignored base paths enter discovery.
        deep_scan_budget: Raw deep-scan override forwarded to keep base and working-tree bounds aligned.

    Returns:
        Counts of the base tree's hook identities, or None when no diff ref was supplied.

    Raises:
        ValueError: If Git cannot resolve or read the requested base.
        ConfigError: If the base analysis configuration cannot be loaded or validated.
    """
    if diff_ref:
        return stable_identities_from_git_base(
            project_root=Path.cwd(),
            paths=paths,
            diff_ref=diff_ref,
            config_path=config_path,
            no_config=no_config,
            include_ignored=include_ignored,
            deep_scan_budget=deep_scan_budget,
        )
    return None
