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
@click.option("--format", "hook_format", type=click.Choice(["json"]), default="json")
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
    "--include-ignored",
    is_flag=True,
    default=False,
    help="Scan default-ignored and .gitignore paths; config ignores still apply.",
)
@click.argument("paths", nargs=-1)
def hook(
    hook_format: str,
    capabilities: bool,
    changed_ranges: str,
    diff_ref: str,
    hook_baseline_path: Path | None,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    paths: tuple[str, ...],
) -> None:
    """Run the additive ``gruff.hook.v1`` agent-hook contract."""
    del hook_format  # --format currently only accepts "json"; reserved for future formats.
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
        )
        report = run_analysis(
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
            )
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


def _hook_base_identities(
    *,
    paths: tuple[str, ...],
    hook_baseline_path: Path | None,
    diff_ref: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
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
        )
    return None
