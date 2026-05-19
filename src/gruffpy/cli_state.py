"""Shared CLI state for Click command callbacks."""

from dataclasses import dataclass

import click


@dataclass(slots=True)
class CliState:
    """Mutable per-run CLI flags (silent/quiet/ansi/no-interaction/verbosity) shared via Click context."""

    is_silent: bool = False
    is_quiet: bool = False
    should_use_ansi: bool | None = None
    is_interaction_disabled: bool = False
    verbosity: int = 0

    @property
    def should_suppress_output(self) -> bool:
        """Return whether user-facing output should be suppressed.

        Returns:
            True when either silent or quiet mode is active.
        """
        return self.is_silent or self.is_quiet


def state(ctx: click.Context | None = None) -> CliState:
    """Return the :class:`CliState` attached to the nearest Click parent context.

    Walks ``ctx.parent`` chain so subcommand callbacks see the state set by
    the root group's option callbacks. Falls back to a fresh default state
    when no context carries one (e.g. unit tests).

    Args:
        ctx: Explicit Click context; defaults to the current active one.

    Returns:
        Shared CLI state — never ``None``.
    """
    current = ctx or click.get_current_context(silent=True)
    while current is not None:
        if isinstance(current.obj, CliState):
            return current.obj
        current = current.parent
    return CliState()
