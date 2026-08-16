"""Render the terminal menu a user sees before choosing a gruff command.

Use this module for the root help journey, including global options and available commands.
It applies the user's colour preference while preserving stable help text and alignment.
"""

import click

from gruffpy.cli_state import state as _state
from gruffpy.version import TOOL_NAME, VERSION


def root_menu(ctx: click.Context) -> str:
    """Render the help screen shown when a user runs gruff-py without a subcommand.

    Use at root dispatch; it joins identity, options, and commands using the selected colour mode.

    Args:
        ctx: Current Click context (carries CLI state and ANSI setting).

    Returns:
        Multi-line help screen, terminated with a blank line.
    """
    return "\n".join(
        [
            *_root_menu_header(ctx),
            *_root_menu_options(ctx),
            *_root_menu_commands(ctx),
            "",
        ]
    )


def _root_menu_header(ctx: click.Context) -> list[str]:
    """Build the tool identity and usage lines at the top of root help.

    Use before options so a CLI user can confirm the version and invocation shape.
    """
    return [
        f"{TOOL_NAME} {_style(VERSION, 'green', ctx)}",
        "",
        _section("Usage:", ctx),
        "  command [options] [arguments]",
        "",
    ]


def _root_menu_options(ctx: click.Context) -> list[str]:
    """Build the global option rows shown in root help.

    Use after the menu header so users can see terminal controls that apply to every command.
    """
    return [
        _section("Options:", ctx),
        _option_line(
            "-h, --help",
            "Display help for the given command. When no command is given display help for the "
            f"{_style('list', 'green', ctx)} command",
            ctx,
        ),
        _option_line("    --silent", "Do not output any message", ctx),
        _option_line(
            "-q, --quiet",
            "Only errors are displayed. All other output is suppressed",
            ctx,
        ),
        _option_line("-V, --version", "Display this application version", ctx),
        _option_line("    --ansi|--no-ansi", "Force (or disable --no-ansi) ANSI output", ctx),
        _option_line("-n, --no-interaction", "Do not ask any interactive question", ctx),
        _option_line(
            "-v|vv|vvv, --verbose",
            "Increase the verbosity of messages: 1 for normal output, 2 for more "
            "verbose output and 3 for debug",
            ctx,
        ),
        "",
    ]


def _root_menu_commands(ctx: click.Context) -> list[str]:
    """Build the command list a user can choose from root help.

    Use after global options; an empty command catalog would leave only the section heading.
    """
    return [
        _section("Available commands:", ctx),
        _command_line("analyse", "Run gruff-py analysis.", ctx),
        _command_line("check-ignore", "Report whether gruff would ignore each path, and why.", ctx),
        _command_line("completion", "Dump the shell completion script", ctx),
        _command_line("dashboard", "Serve the local gruff-py dashboard.", ctx),
        _command_line("help", "Display help for a command", ctx),
        _command_line("hook", "Run gruff-py analysis for an agent hook.", ctx),
        _command_line("init", "Write a default .gruff-py.yaml to the current directory.", ctx),
        _command_line("list", "List commands", ctx),
        _command_line("list-rules", "List gruff-py rule metadata.", ctx),
        _command_line("migrate-config", "Rewrite legacy config keys to the current schema.", ctx),
        _command_line("report", "Render a gruff-py report to stdout or a file.", ctx),
        _command_line(
            "summary",
            "Print a compact digest of a scan: per-pillar finding counts, top rules, and top "
            "file offenders. Runs the analyser once and renders only the summary; no "
            "per-finding spam.",
            ctx,
        ),
    ]


def _section(label: str, ctx: click.Context) -> str:
    """Style a root-help section label using the user's colour choice.

    Use when joining menu sections; empty text remains empty and receives no visible content.
    """
    return _style(label, "yellow", ctx)


def _option_line(label: str, description: str, ctx: click.Context) -> str:
    """Align one global option with the explanation shown beside it.

    Use while building root help; empty labels still reserve the normal option column.
    """
    return f"  {_style(label, 'green', ctx)}{' ' * (22 - len(label))}{description}"


def _command_line(name: str, description: str, ctx: click.Context) -> str:
    """Align one command name with the action a CLI user can take.

    Use while building the command list; empty names still preserve the display gutter.
    """
    # Pad past the longest command name ("migrate-config", 14) so every description
    # keeps a column gutter; a width equal to the name length renders them flush.
    return f"  {_style(name, 'green', ctx)}{' ' * (16 - len(name))}{description}"


def _style(text: str, color: str, ctx: click.Context) -> str:
    """Apply terminal colour only when the user's effective setting permits it.

    Use for help labels and names; empty text stays empty whether colour is enabled or disabled.
    """
    # Disabled ANSI means the user receives plain text suitable for redirected or colourless output.
    if should_use_color(ctx) is False:
        return text
    return click.style(text, fg=color)


def should_use_color(ctx: click.Context) -> bool | None:
    """Resolve the colour choice that applies to the current help output.

    Use before styling; command input wins, then shared state, then Click's terminal detection.
    None means the user made no choice and Click decides from the output environment.

    Args:
        ctx: Current Click context.

    Returns:
        True or False to force colour; None means the caller should defer to Click.
    """
    parameters = getattr(ctx, "params", {})
    # A command-local ANSI choice is the most specific preference the user supplied.
    if "ansi" in parameters:
        value = parameters["ansi"]
        # Click may expose non-boolean test data; only a real flag value can override colour.
        if isinstance(value, bool):
            return value
    state = _state(ctx)
    # Root-level ANSI state applies when this command did not carry its own flag value.
    if state.should_use_ansi is not None:
        return state.should_use_ansi
    return ctx.color
