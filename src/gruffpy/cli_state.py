"""Share global output and interaction choices across Click callbacks.

Use this module after a CLI user selects silent, quiet, colour, or interaction options.
Subcommands read the nearest state so every step of one command follows the same terminal behaviour.
"""

from dataclasses import dataclass

import click


@dataclass(slots=True)
class CliState:
    """Hold the terminal behaviour selected for one CLI invocation.

    Use this state on the root Click context before dispatching a subcommand.
    Child callbacks update or read it to keep prompts, colour, and output consistent for the user.

    Attributes:
        is_silent: Whether command output should be fully suppressed.
        is_quiet: Whether non-essential command output should be suppressed.
        should_use_ansi: Optional override for ANSI colour output.
        is_interaction_disabled: Whether prompts and interactive flows are disabled.
        verbosity: Verbosity level requested by CLI flags.
    """

    is_silent: bool = False
    is_quiet: bool = False
    should_use_ansi: bool | None = None
    is_interaction_disabled: bool = False
    verbosity: int = 0

    @property
    def should_suppress_output(self) -> bool:
        """Report whether the current CLI choices hide normal output.

        Use before writing to the terminal; the value is always true or false, never absent.

        Returns:
            True when either silent or quiet mode is active.
        """
        return self.is_silent or self.is_quiet


def state(ctx: click.Context | None = None) -> CliState:
    """Find the terminal choices attached to the nearest Click context.

    Use from any subcommand callback; no explicit context searches Click's active command.
    When no context supplies CLI state, defaults leave output and interaction enabled.

    Args:
        ctx: Explicit context; None searches the active command. No active command uses defaults.

    Returns:
        The nearest context's existing CLI state, or a fresh default state when none is attached.
    """
    current = ctx or click.get_current_context(silent=True)
    # A subcommand without its own CLI state can reuse terminal choices from a parent context.
    while current is not None:
        # The nearest settings take precedence if several contexts supply CLI state.
        if isinstance(current.obj, CliState):
            return current.obj
        current = current.parent
    return CliState()
