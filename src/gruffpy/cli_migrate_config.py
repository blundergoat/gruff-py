"""Run the terminal workflow for `gruff-py migrate-config`.

A dry run shows the proposed YAML changes so the user can review them.
A write goes to the chosen destination while preserving the original configuration for rollback.
"""

from __future__ import annotations

from pathlib import Path

import click

from gruffpy.command.migrate_config import migrate_config_file
from gruffpy.config.exceptions import ConfigError


@click.command("migrate-config", help="Rewrite legacy config keys to the current schema.")
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    default=False,
    help="Print the migration diff without writing the file.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help=("Path to the YAML config to migrate (.yaml or .yml). Defaults to the discovered project config."),
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Where to write the migrated config. Required unless --dry-run; the input is never rewritten.",
)
def migrate_config(dry_run: bool, config_path: Path | None, output_path: Path | None) -> None:
    """Print what a YAML migration would change and write it on request.

    Updates schemaVersion and eligible legacy rule tiers, moves per-command minimumSeverity to failOn and removes allowlists.secretPreviews.
    Preserves paths.ignore and requires a separate output path for changes. FAMILY-CONTRACT.md section 5 governs preview removal.

    Args:
        dry_run: When True, show any changes without writing the migrated configuration.
        config_path: Explicit YAML config path, or None to discover the project config.
        output_path: Destination for changed YAML. None is allowed for dry runs and when the input is already current.

    Returns:
        None. Prints any migration notes and diff, warns if YAML comments would be lost, and reports a successful write.

    Raises:
        click.ClickException: If migration raises ConfigError, a write has no distinct resolved output path, or the output write fails.
    """
    try:
        migration = migrate_config_file(project_root=Path.cwd(), config_path=config_path)
    except ConfigError as exc:
        # If old and new gate settings disagree, show the conflict before offering a converted file.
        raise click.ClickException(str(exc)) from exc
    # Show discarded legacy settings and other review notes before the proposed diff.
    for note in migration.notes:
        click.echo(f"Note: {note}")
    # A current input needs no output file, even when the caller named one.
    if not migration.has_changes():
        click.echo(f"{migration.path} is already current; no changes.")
        return
    click.echo("Migration changes:")
    # Summarise each setting change before showing the full YAML diff.
    for change in migration.changes:
        click.echo(f"  - {change}")
    click.echo("\n" + migration.diff(), nl=False)
    # Users can copy any YAML rationale they need after reading the warning and reviewing the diff.
    if migration.will_lose_comments():
        click.echo("Note: YAML comments are not preserved by migration; review the diff.")
    # A dry run is a review step and does not touch either file.
    if dry_run:
        click.echo(f"Dry run: {migration.path} left unchanged.")
        return
    # Require the caller to choose where changed YAML goes so migration preserves the input by default.
    if output_path is None:
        raise click.ClickException("migrate-config needs --output <path> to write the migrated config, or --dry-run to print it.")
    try:
        # Two paths can name the same file through a hard link. Always keep the original as a rollback copy.
        if output_path.resolve() == migration.path.resolve() or (output_path.exists() and output_path.samefile(migration.path)):
            raise click.ClickException(f"--output must name a different file from --config; {migration.path} is the copy you may want back.")
        with click.open_file(str(output_path), mode="w", encoding="utf-8", atomic=True) as output:
            output.write(migration.migrated_text)
    except OSError as exc:
        # A destination under a read-only directory gives the operator a write error with the path to change.
        raise click.ClickException(f"Unable to write {output_path}: {exc}") from exc
    click.echo(f"Wrote {output_path}; {migration.path} is unchanged.")
