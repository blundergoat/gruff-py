"""Click command for ``gruff-py migrate-config``.

The ``migrate-config`` subcommand lives in its own module so its CLI wiring
sits next to the rewrite logic in :mod:`gruffpy.command.migrate_config`
without growing :mod:`gruffpy.cli`. It is registered on the root group from
:mod:`gruffpy.cli`.
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
    help=(
        "Path to the YAML config to migrate (.yaml or .yml). Defaults to the "
        "discovered project config."
    ),
)
def migrate_config(dry_run: bool, config_path: Path | None) -> None:
    """Rewrite legacy config keys to the current schema, printing a diff summary.

    Maps the pre-ADR-014 two-tier ``thresholds: {warning, error}`` rubric to a
    single ``threshold`` plus ``severity`` (the error tier wins when both are
    present) and pins ``schemaVersion``. Allowlists, ``paths.ignore``,
    ``selection``, ``minimumSeverity``, per-rule ``enabled`` and ``options``
    are preserved.

    Args:
        dry_run: When True, print the diff without writing the file.
        config_path: Explicit YAML config path, or ``None`` to discover the
            project config.

    Raises:
        click.ClickException: When no migratable YAML config exists or the
            file cannot be parsed or written.
    """
    try:
        migration = migrate_config_file(project_root=Path.cwd(), config_path=config_path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    for note in migration.notes:
        click.echo(f"Note: {note}")
    if not migration.has_changes():
        click.echo(f"{migration.path} is already current; no changes.")
        return
    click.echo("Migration changes:")
    for change in migration.changes:
        click.echo(f"  - {change}")
    click.echo("\n" + migration.diff(), nl=False)
    if migration.will_lose_comments():
        click.echo("Note: YAML comments are not preserved by migration; review the diff.")
    if dry_run:
        click.echo(f"Dry run: {migration.path} left unchanged.")
        return
    try:
        migration.path.write_text(migration.migrated_text, encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"Unable to write {migration.path.name}: {exc}") from exc
    click.echo(f"Wrote {migration.path}")
