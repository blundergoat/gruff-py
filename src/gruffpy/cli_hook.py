"""Click command for the ``gruff.hook.v1`` agent-hook contract.

The ``hook`` subcommand lives in its own module so its CLI wiring sits next to
the projection logic in :mod:`gruffpy.hook_contract` without growing
:mod:`gruffpy.cli`. It is registered on the root group from :mod:`gruffpy.cli`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.runner import run_analysis
from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.hook_contract import (
    capabilities_payload,
    config_error_payload,
    hook_payload,
    render_json,
    stable_identities_from_baseline,
    stable_identities_from_git_base,
)
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter


@click.command("hook", help="Run gruff-py analysis for an agent hook.")
# The flag stays accepted and Choice-validated; the callback never used its value.
@click.option(
    "--format",
    "hook_format",
    type=click.Choice(["json"]),
    default="json",
    expose_value=False,
)
@click.option("--capabilities", is_flag=True, default=False, help="Emit hook capabilities JSON.")
@click.option(
    "--changed-ranges",
    default="",
    help='Explicit changed line ranges such as "3-3,8-10".',
)
@click.option("--diff", "diff_ref", default="", help="Git ref for hook new-only comparison.")
@click.option(
    "--baseline",
    "hook_baseline_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Hook or analysis JSON file for stableIdentity new-only comparison.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a gruff YAML or TOML config file.",
)
@click.option("--no-config", is_flag=True, default=False, help="Skip config loading.")
@click.option(
    "--deep-scan-budget",
    default="",
    help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
)
@click.option(
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Scan default-ignored and .gitignore paths; config ignores still apply.",
)
@click.option(
    "--exclude-rule",
    multiple=True,
    help="Execution-level rule IDs to skip; accepts comma-separated or repeated values.",
)
@click.argument("paths", nargs=-1)
# gruff: disable-next=docs.missing-param-doc -- option help= text documents each flag.
def hook(
    capabilities: bool,
    changed_ranges: str,
    diff_ref: str,
    hook_baseline_path: Path | None,
    config_path: Path | None,
    no_config: bool,
    deep_scan_budget: str,
    include_ignored: bool,
    exclude_rule: tuple[str, ...],
    paths: tuple[str, ...],
) -> None:
    """Run the additive ``gruff.hook.v1`` agent-hook contract."""
    _execute_hook(
        capabilities=capabilities,
        changed_ranges=changed_ranges,
        diff_ref=diff_ref,
        hook_baseline_path=hook_baseline_path,
        config_path=config_path,
        no_config=no_config,
        deep_scan_budget=deep_scan_budget,
        include_ignored=include_ignored,
        exclude_rule=exclude_rule,
        paths=paths,
    )


def _execute_hook(
    *,
    capabilities: bool,
    changed_ranges: str,
    diff_ref: str,
    hook_baseline_path: Path | None,
    config_path: Path | None,
    no_config: bool,
    deep_scan_budget: str,
    include_ignored: bool,
    exclude_rule: tuple[str, ...],
    paths: tuple[str, ...],
) -> None:
    """Run one hook invocation and exit, so the decorated command stays a thin entry point.

    Args:
        capabilities: When True, emit the capabilities payload and exit before any analysis.
        changed_ranges: Explicit changed line ranges such as ``3-3,8-10``; empty for none.
        diff_ref: Git ref for new-only comparison; empty when no ``--diff`` was given.
        hook_baseline_path: Hook or analysis JSON supplying base identities, or None.
        config_path: Explicit config file, or None to discover the project default.
        no_config: Whether config discovery is disabled.
        include_ignored: Whether default-ignored and gitignored paths are scanned.
        deep_scan_budget: Raw ``--deep-scan-budget`` text, or empty when unset.
        exclude_rule: Execution-level rule ids to skip, comma-separated or repeated.
        paths: Requested hook paths; empty means the current directory.
    """
    # Lazy import avoids a cli <-> cli_hook import cycle at module load.
    from gruffpy.cli import _write_stdout

    if capabilities:
        _write_stdout(render_json(capabilities_payload()))
        sys.exit(0)
    if hook_baseline_path is not None and diff_ref:
        click.echo("--baseline and --diff cannot be combined in hook mode.", err=True)
        sys.exit(2)

    try:
        base_identities = _hook_base_identities(
            paths=paths,
            hook_baseline_path=hook_baseline_path,
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
        # Build the payload inside the try: a malformed --changed-ranges value
        # raises ValueError here, which must surface as a controlled exit 2 rather
        # than an uncaught traceback that breaks the stable hook contract.
        payload = hook_payload(
            report,
            paths=paths or (".",),
            changed_ranges=changed_ranges,
            base_stable_identities=base_identities,
        )
    except ConfigError as exc:
        _write_stdout(render_json(config_error_payload(exc)))
        sys.exit(2)
    except ValueError as exc:
        click.echo(str(exc), err=True)
        sys.exit(2)

    _write_stdout(render_json(payload))
    sys.exit(0)


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
    hook_baseline_path: Path | None,
    diff_ref: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    deep_scan_budget: str,
) -> frozenset[str] | None:
    """Resolve hook base stable identities for ``--baseline`` / ``--diff`` runs."""
    if hook_baseline_path is not None:
        return stable_identities_from_baseline(hook_baseline_path)
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
