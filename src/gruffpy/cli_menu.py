"""Symfony-style root help menu rendering."""

import click

from gruffpy.cli_state import state as _state
from gruffpy.version import TOOL_NAME, VERSION


def root_menu(ctx: click.Context) -> str:
    """Render the Symfony-style help screen shown when ``gruff-py`` runs without a subcommand.

    Joins three sections - header (tool/version + usage line), global
    options, and the available-commands list - into one terminal-friendly
    string. ANSI styling honours ``--ansi``/``--no-ansi`` via
    :func:`should_use_color`.

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
    return [
        f"{TOOL_NAME} {_style(VERSION, 'green', ctx)}",
        "",
        _section("Usage:", ctx),
        "  command [options] [arguments]",
        "",
    ]


def _root_menu_options(ctx: click.Context) -> list[str]:
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
    return _style(label, "yellow", ctx)


def _option_line(label: str, description: str, ctx: click.Context) -> str:
    return f"  {_style(label, 'green', ctx)}{' ' * (22 - len(label))}{description}"


def _command_line(name: str, description: str, ctx: click.Context) -> str:
    # Pad past the longest command name ("check-ignore", 12) so every description
    # keeps a column gutter; a width equal to the name length renders them flush.
    return f"  {_style(name, 'green', ctx)}{' ' * (14 - len(name))}{description}"


def _style(text: str, color: str, ctx: click.Context) -> str:
    if should_use_color(ctx) is False:
        return text
    return click.style(text, fg=color)


def should_use_color(ctx: click.Context) -> bool | None:
    """Resolve whether ANSI color should be applied for the current context.

    Precedence: an ``ansi`` parameter on *ctx*, then the ``should_use_ansi``
    flag from the shared :class:`CliState`, then Click's own ``ctx.color``
    (which respects ``NO_COLOR`` and TTY detection). ``None`` means "let
    Click decide".

    Args:
        ctx: Current Click context.

    Returns:
        ``True``/``False`` to force color on/off; ``None`` to defer to Click.
    """
    parameters = getattr(ctx, "params", {})
    if "ansi" in parameters:
        value = parameters["ansi"]
        if isinstance(value, bool):
            return value
    state = _state(ctx)
    if state.should_use_ansi is not None:
        return state.should_use_ansi
    return ctx.color
