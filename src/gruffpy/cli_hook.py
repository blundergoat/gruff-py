"""Click command for the ``gruff.hook.v2`` agent-hook contract.

The ``hook`` subcommand lives in its own module so its CLI wiring sits next to
the projection logic in :mod:`gruffpy.hook_contract` without growing
:mod:`gruffpy.cli`. It is registered on the root group from :mod:`gruffpy.cli`.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

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
    """Attach every hook option to the command, so the callback declares one kwargs map rather than fourteen names.

    Args:
        command: The Click callback the options decorate.

    Returns:
        The callback with every hook option applied, innermost last as Click expects.
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
        default="",
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
    """Run the additive ``gruff.hook.v2`` agent-hook contract."""
    # Lazy import avoids a cli <-> cli_hook import cycle at module load.
    from gruffpy.cli import _write_stdout

    # A probe wants the feature list and nothing else, so it is answered before any run is described.
    if bool(kwargs["capabilities"]):
        _write_stdout(render_json(capabilities_payload()))
        sys.exit(0)

    _execute_hook(
        changed_ranges=str(kwargs["changed_ranges"]),
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
    changed_ranges: str,
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
        changed_ranges: Explicit changed line ranges such as ``3-3,8-10``; empty for none.
        diff_ref: Git ref for new-only comparison; empty when no ``--diff`` was given.
        hook_baseline_path: Ratified baseline v3 file to apply, or None.
        config_path: Explicit config file, or None to discover the project default.
        no_config: Whether config discovery is disabled.
        include_ignored: Whether default-ignored and gitignored paths are scanned.
        deep_scan_budget: Raw ``--deep-scan-budget`` text, or empty when unset.
        exclude_rule: Execution-level rule ids to skip, comma-separated or repeated.
        gate: What the caller asked the hook to block on.
        paths: Requested hook paths; empty means the current directory.
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
        # A baseline this port cannot read would otherwise suppress findings under rules nobody ratified.
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
    """Return everything the run found, before any display floor narrowed it.

    A project that sets ``minimumSeverity: error`` is saying which findings it
    wants to read, not which ones may block an edit. Publishing the filtered set
    would let that reading preference decide what an agent is told about and
    what the gate can see, which is the one thing the display floor must never
    do.

    Args:
        report: The report the analyser produced.

    Returns:
        The pre-display findings when a filter narrowed them, and the reported
        findings otherwise.
    """
    return report.machine_context.summary_findings or report.findings


def _report_with(report: AnalysisReport, findings: tuple[Finding, ...]) -> AnalysisReport:
    """Return the report with its findings replaced, leaving every other field alone.

    Args:
        report: The analysis report the run produced.
        findings: The set a baseline left for the caller to act on.

    Returns:
        A copy carrying the gated findings.
    """
    return replace(report, findings=findings)


def _run_mode(changed_ranges: str, diff_ref: str) -> str:
    """Name which region selector chose the work, so a consumer can tell a targeted run from a whole-tree one.

    Args:
        changed_ranges: Raw ``--changed-ranges`` text, empty when unset.
        diff_ref: Raw ``--diff`` ref, empty when unset.

    Returns:
        One of ``changed-ranges``, ``diff`` or ``full``.
    """
    # Explicit ranges are the narrowest selector and win when both are given.
    if changed_ranges:
        return "changed-ranges"
    return "diff" if diff_ref else "full"


def _apply_hook_baseline(
    findings: tuple[Finding, ...],
    baseline_path: Path | None,
) -> tuple[tuple[Finding, ...], dict[int, str]]:
    """Apply a ``--baseline`` file, classifying every finding it covers.

    The hook reads the same ratified baseline v3 file ``analyse
    --generate-baseline`` writes, so one review carries across both surfaces. A
    file in any other schema is refused rather than read under the wrong rules.

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

    What blocks an edit is exactly what the agent was shown: a finding the
    changed-region filter or the baseline removed is not in the payload and does
    not block.

    Args:
        payload: The published hook report.
        gate: What the caller asked the hook to block on.

    Returns:
        0 when nothing reached the gate, 1 when something did.
    """
    diagnostics = payload.get("diagnostics")
    # A consumer may ask for any caveat to stop the edit, which is the only way a warning becomes blocking.
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
) -> frozenset[str] | None:
    """Resolve hook base stable identities for a ``--diff`` run.

    A ``--baseline`` run no longer goes through here: it applies a ratified
    baseline v3 file, which classifies findings rather than matching hook-local
    identities.
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
