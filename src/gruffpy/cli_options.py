"""Define the options users see across the gruff-py command tree.

Command decorators keep shared Click parsing and help text consistent while
each command implementation stays focused on the user's requested journey.
"""

import inspect
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar, cast

import click

from gruffpy.analysis.baseline import DEFAULT_BASELINE_FILENAME
from gruffpy.cli_state import state as _state
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.severity import Severity
from gruffpy.version import TOOL_NAME, VERSION

_F = TypeVar("_F", bound=Callable[..., Any])
ClickDecorator = Callable[[Callable[..., Any]], Callable[..., Any]]
_command_root: click.Group | None = None


class _AnalyseCommand(click.Command):
    """Teach Click how to read an optional baseline destination.

    - `--generate-baseline reviewed.json` writes that file, the spelling every gruff port accepts.
    - `--generate-baseline src` writes the default baseline and scans `src`, so a source file is never overwritten with JSON.
    - `--generate-baseline=PATH` names any other destination.
    """

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """Give the bare baseline flag its default unless the next word names a `.json` destination.

        Use this before Click parses paths so a command such as `analyse --generate-baseline src` still scans `src`.

        Args:
            ctx: Click context for this invocation.
            args: Raw analyse arguments, including any end-of-options marker.

        Returns:
            Positional arguments left by Click after it parses the options.
        """
        # Only the analyse option needs expansion. Leave ordinary operands for Click to interpret.
        for index, argument in enumerate(args):
            # The user can use `--` to pass a literal filename that starts with a dash.
            if argument == "--":
                break
            # Every other argument is an operand or an option Click already understands.
            if argument != "--generate-baseline":
                continue
            next_argument = args[index + 1] if index + 1 < len(args) else ""
            # `--generate-baseline reviewed.json` names the destination, so Click reads the next word as its value.
            if next_argument.endswith(".json") and not next_argument.startswith("-"):
                continue
            # A scan target such as `target.py`, another option, or nothing at all follows, so use the standard destination.
            args[index] = f"--generate-baseline={DEFAULT_BASELINE_FILENAME}"
        return super().parse_args(ctx, args)


def was_fail_on_set_on_cli() -> bool:
    """Return True when the user explicitly passed ``--fail-on`` on the command line.

    Explicit CLI input takes precedence over failOn.<cmd>, which takes precedence over the binary default.

    Returns:
        True when Click records COMMANDLINE for fail_on. False for every other source or when there is no active Click context.
    """
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    source = ctx.get_parameter_source("fail_on")
    return source == click.core.ParameterSource.COMMANDLINE


def bind_root_group(root: click.Group) -> None:
    """Bind the parent Click group used by command-registration decorators.

    Call once during CLI bootstrap before applying command decorators, which otherwise raise RuntimeError.

    Args:
        root: Click root group that owns every gruff subcommand.

    Returns:
        None; replaces the shared root-group binding.
    """
    global _command_root
    _command_root = root


def apply_decorators(function: _F, decorators: Iterable[ClickDecorator]) -> _F:
    """Compose command decorators that may attach option metadata or register the command.

    Args:
        function: The Click command function to decorate.
        decorators: Wrappers applied from left to right; an empty iterable returns function unchanged.

    Returns:
        The resulting callable, which may be a registered Click command. Its static type matches the input signature.
    """
    wrapped: Callable[..., Any] = function
    for decorator in decorators:
        wrapped = decorator(wrapped)
    return cast(_F, wrapped)


def _ignored_flag_option(name: str, help_text: str) -> Callable[[_F], _F]:
    """Accept a compatibility flag without forwarding it to the command implementation.

    Args:
        name: Option declaration accepted by Click.
        help_text: User-facing explanation included in command help.

    Returns:
        An option decorator with a false default and no exposed command argument.
    """
    return click.option(name, is_flag=True, default=False, expose_value=False, help=help_text)


def _ignored_string_option(
    name: str,
    help_text: str,
    default: str | None = None,
) -> Callable[[_F], _F]:
    """Accept a compatibility value without forwarding it to the command implementation.

    Args:
        name: Option declaration accepted by Click.
        help_text: User-facing explanation included in command help.
        default: Value used when the option is omitted, including None when no replacement is supplied.

    Returns:
        An option decorator that parses the value but does not expose a command argument.
    """
    return click.option(name, default=default, expose_value=False, help=help_text)


def _ignored_path_option(name: str, help_text: str) -> Callable[[_F], _F]:
    """Accept a compatibility path without forwarding it to the command implementation.

    Args:
        name: Option declaration accepted by Click.
        help_text: User-facing explanation included in command help.

    Returns:
        A Path-valued option decorator with no command argument and None when omitted.
    """
    return click.option(
        name,
        type=click.Path(path_type=Path),
        default=None,
        expose_value=False,
        help=help_text,
    )


def _path_option(name: str, parameter_name: str, help_text: str) -> Callable[[_F], _F]:
    """Expose an optional CLI path under the command's chosen parameter name.

    Args:
        name: Option spelling accepted from the user.
        parameter_name: Keyword name receiving the parsed path in the command implementation.
        help_text: User-facing explanation included in command help.

    Returns:
        A Path-valued option decorator whose omitted value is None.
    """
    return click.option(
        name,
        parameter_name,
        type=click.Path(path_type=Path),
        default=None,
        help=help_text,
    )


def _ignored_int_option(name: str, help_text: str) -> Callable[[_F], _F]:
    """Validate a compatibility integer without exposing it to the command implementation.

    Args:
        name: Option declaration accepted by Click.
        help_text: User-facing explanation included in command help.

    Returns:
        An integer option decorator with no exposed command argument and None when omitted.
    """
    return click.option(name, type=int, default=None, expose_value=False, help=help_text)


def _silent_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Enable full output suppression when the silent flag is supplied.

    Args:
        ctx: Click context used to locate the shared CLI state.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: True enables silence; False leaves the existing state unchanged.

    Returns:
        None; sets the shared silent flag only when value is true.
    """
    if value:
        _state(ctx).is_silent = True


def _quiet_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Enable normal-output suppression when the quiet flag is supplied.

    Args:
        ctx: Click context used to locate the shared CLI state.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: True enables quiet mode; False leaves the existing state unchanged.

    Returns:
        None; sets the shared quiet flag only when value is true.
    """
    if value:
        _state(ctx).is_quiet = True


def _ansi_callback(ctx: click.Context, _param: click.Parameter, value: bool | None) -> None:
    """Apply an explicit colour choice to Click and the shared CLI state.

    Args:
        ctx: Context receiving the colour choice and used to locate shared state.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: True or False forces colour on or off; None preserves both existing settings.

    Returns:
        None; updates Click and shared colour state only for an explicit value.
    """
    if value is not None:
        ctx.color = value
        _state(ctx).should_use_ansi = value


def _no_interaction_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Disable interactive prompts when the no-interaction flag is supplied.

    Args:
        ctx: Click context used to locate the shared CLI state.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: True disables interaction; False leaves the existing state unchanged.

    Returns:
        None; updates the shared interaction policy only when value is true.
    """
    if value:
        _state(ctx).is_interaction_disabled = True


def _verbose_callback(ctx: click.Context, _param: click.Parameter, value: int) -> None:
    """Store a requested verbosity level without clearing an existing level for zero.

    Args:
        ctx: Click context used to locate the shared CLI state.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: Requested level; a nonzero value replaces the shared verbosity setting.

    Returns:
        None; replaces shared verbosity only when value is nonzero.
    """
    if value:
        _state(ctx).verbosity = value


def _command_version_callback(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Print the tool version and finish an ordinary version-only invocation.

    Args:
        ctx: Context whose resilient-parsing mode suppresses output and whose exit ends the command.
        _param: Click-supplied parameter descriptor, unused by this callback.
        value: True requests the version; False leaves command dispatch unchanged.

    Returns:
        None when the version is not requested or resilient parsing is active.

    Raises:
        click.exceptions.Exit: With a successful status after printing outside resilient parsing.
    """
    if value and not ctx.resilient_parsing:
        click.echo(f"{TOOL_NAME} {VERSION}")
        ctx.exit()


def _option(*param_decls: str, **attrs: Any) -> ClickDecorator:
    """Create a Click option decorator with the shared command-decorator type.

    Args:
        param_decls: Option spellings and any explicit destination name passed to Click.
        attrs: Click option settings, including parsing, help and callback behavior.

    Returns:
        The option decorator, without changing Click's parsing or registration behavior.
    """
    return cast(ClickDecorator, click.option(*param_decls, **attrs))


def _argument(*param_decls: str, **attrs: Any) -> ClickDecorator:
    """Create a Click positional-argument decorator for a command signature.

    Args:
        param_decls: Argument declaration passed to Click.
        attrs: Click argument settings such as required status, arity and value type.

    Returns:
        The argument decorator with the shared command-decorator type.
    """
    return cast(ClickDecorator, click.argument(*param_decls, **attrs))


def _command(*args: Any, **attrs: Any) -> ClickDecorator:
    """Build a decorator that registers a command on the bound root group.

    Args:
        args: Positional arguments for root.command; omission lets Click derive the command name.
        attrs: Click settings; omitted help uses the first docstring paragraph, while help=None lets Click use the full docstring.

    Returns:
        A registration decorator that fills omitted help from the command implementation's docstring.

    Raises:
        RuntimeError: When the returned decorator is applied before bind_root_group has supplied a root group.
    """

    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        """Register function as a subcommand of the bound root group.

        Args:
            function: The command implementation to register.

        Returns:
            The Click-wrapped command callable.

        Raises:
            RuntimeError: If bind_root_group has not supplied a root group.
        """
        if _command_root is None:
            raise RuntimeError("CLI root group has not been bound.")
        command_attrs = dict(attrs)
        command_attrs.setdefault("help", _doc_summary(function))
        return cast(Callable[..., Any], _command_root.command(*args, **command_attrs)(function))

    return decorator


def _doc_summary(function: Callable[..., Any]) -> str:
    """Return the first docstring paragraph for Click command help.

    Args:
        function: Command implementation whose cleaned docstring supplies its default help text.

    Returns:
        The first paragraph after indentation cleanup, or empty text when no docstring is available.
    """
    doc = inspect.getdoc(function) or ""
    return doc.split("\n\n", 1)[0]


def _pass_context(function: _F) -> _F:
    """Arrange for Click to pass its current context into a command implementation.

    Args:
        function: Command callable expecting the context as its first argument.

    Returns:
        Click's context-passing wrapper, cast to the original callable type for decorator composition.
    """
    return cast(_F, click.pass_context(function))


def analyse_command(function: _F) -> _F:
    """Register the analyse subcommand with global, analysis and cross-port compatibility options.

    Args:
        function: Command implementation to decorate and register on the bound root group.

    Returns:
        The decorated callable registered as the gruff-py analyse command.
    """
    return apply_decorators(function, _ANALYSE_COMMAND_DECORATORS)


def dashboard_command(function: _F) -> _F:
    """Register the dashboard subcommand serving the live HTTP interface.

    Adds the dashboard launch options on top of the global flags. Diff and
    timeout stay accepted family options but do not alter gruff-py scans.

    Args:
        function: Command implementation to decorate and register as dashboard.

    Returns:
        The decorated callable registered as the gruff-py dashboard command.
    """
    return apply_decorators(function, _DASHBOARD_COMMAND_DECORATORS)


def list_rules_command(function: _F) -> _F:
    """Wire *function* up as the ``list-rules`` subcommand (table or JSON output).

    Plain text output is also available.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py list-rules on the bound root group.
    """
    return apply_decorators(function, _LIST_RULES_COMMAND_DECORATORS)


def report_command(function: _F) -> _F:
    """Register the report subcommand for writing HTML or JSON to stdout or a file.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py report on the bound root group.
    """
    return apply_decorators(function, _REPORT_COMMAND_DECORATORS)


def summary_command(function: _F) -> _F:
    """Register the summary subcommand for capped text digests or a findings-free JSON projection.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py summary on the bound root group.
    """
    return apply_decorators(function, _SUMMARY_COMMAND_DECORATORS)


def metric_calibration_command(function: _F) -> _F:
    """Register the hidden metric-calibration subcommand.

    Hidden from --help listings, this command shows how metric values are distributed across the codebase during rule tuning.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py metric-calibration on the bound root group.
    """
    return apply_decorators(function, _METRIC_CALIBRATION_COMMAND_DECORATORS)


def list_command(function: _F) -> _F:
    """Register the list subcommand for discovering available commands.

    The --format flag selects txt, xml, json or md. The --raw flag prints command names only and takes precedence.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py list on the bound root group.
    """
    return apply_decorators(function, _LIST_COMMAND_DECORATORS)


def help_command_decorator(function: _F) -> _F:
    """Register the help subcommand for displaying per-command help text.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py help on the bound root group.
    """
    return apply_decorators(function, _HELP_COMMAND_DECORATORS)


def init_command(function: _F) -> _F:
    """Register the init subcommand for writing a default .gruff-py.yaml file.

    Adds --force to regenerate an existing file on top of the global flags.

    Args:
        function: The command implementation.

    Returns:
        The Click command registered as gruff-py init on the bound root group.
    """
    return apply_decorators(function, _INIT_COMMAND_DECORATORS)


def check_ignore_command(function: _F) -> _F:
    """Register the check-ignore subcommand with shared config resolution and ignore classification.

    The command reports each path's ignore status and reason without running analysis.

    Args:
        function: Command implementation to decorate and register as check-ignore.

    Returns:
        The decorated callable registered as the gruff-py check-ignore command.
    """
    return apply_decorators(function, _CHECK_IGNORE_COMMAND_DECORATORS)


def completion_command(function: _F) -> _F:
    """Register the completion subcommand for shell completion scripts.

    The debug flag is accepted, but invoking it raises a not-implemented error.

    Args:
        function: Command implementation to decorate and register as completion.

    Returns:
        The decorated callable registered as the gruff-py completion command.
    """
    return apply_decorators(function, _COMPLETION_COMMAND_DECORATORS)


_GLOBAL_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _option(
        "--silent",
        is_flag=True,
        expose_value=False,
        callback=_silent_callback,
        help="Do not output any message.",
    ),
    _option(
        "-q",
        "--quiet",
        is_flag=True,
        expose_value=False,
        callback=_quiet_callback,
        help="Only errors are displayed. All other output is suppressed.",
    ),
    _option(
        "-V",
        "--version",
        is_flag=True,
        expose_value=False,
        is_eager=True,
        callback=_command_version_callback,
        help="Display this application version.",
    ),
    _option(
        "--ansi/--no-ansi",
        default=None,
        expose_value=False,
        callback=_ansi_callback,
        help="Force or disable ANSI output.",
    ),
    _option(
        "-n",
        "--no-interaction",
        is_flag=True,
        expose_value=False,
        callback=_no_interaction_callback,
        help="Do not ask any interactive question.",
    ),
    _option(
        "-v",
        "--verbose",
        count=True,
        expose_value=False,
        callback=_verbose_callback,
        help="Increase message verbosity. Use -v, -vv, or -vvv.",
    ),
)

_ANALYSIS_COMPAT_DECORATORS: tuple[ClickDecorator, ...] = (
    _ignored_path_option("--infection-report", "Path to a full Infection JSON report to ingest."),
    _ignored_flag_option("--infection-run", "Run Infection before ingesting --infection-report."),
    _ignored_string_option("--infection-bin", "Infection executable for --infection-run.", "infection"),
    _ignored_path_option("--infection-config", "Path to infection.json5 for --infection-run."),
    _ignored_string_option(
        "--infection-test-framework-options",
        "Options passed to Infection/PHPUnit for --infection-run.",
    ),
    _ignored_path_option(
        "--mutation-baseline",
        "Path to a baseline Infection JSON report for MSI diff mode.",
    ),
    _ignored_int_option("--mutation-budget", "Maximum escaped/timed-out mutants allowed."),
    _option(
        "--diff",
        "diff_mode",
        default="",
        help=("Filter findings to changed regions. Use working-tree, staged, unstaged, a base ref, or - for unified diff on stdin."),
    ),
    _option("--since", default="", help="Git base ref for changed-region filtering."),
    _option(
        "--changed-ranges",
        type=str,
        default=None,
        help='Explicit changed line ranges such as "3-3,8-10".',
    ),
    _option(
        "--changed-scope",
        type=click.Choice(["symbol", "hunk"]),
        default="symbol",
        show_default=True,
        help="Changed-region scope: symbol or hunk.",
    ),
    _option("--diff-vs", default="", help="Superseded spelling of --diff-base; identical behaviour."),
    _ignored_flag_option("--changed-only", "With --diff-base, compare only changed files."),
    _ignored_path_option(
        "--paths-relative-to",
        "Normalize absolute finding paths relative to this directory for reports.",
    ),
    _ignored_path_option("--history-file", "Append score trend history to this JSON file."),
    _path_option(
        "--baseline-path",
        "baseline_path",
        "Superseded spelling of --baseline; identical behaviour, and it warns.",
    ),
    _option(
        "--generate-baseline",
        "generate_baseline",
        default=None,
        type=click.Path(path_type=Path),
        help=f'Write current findings to "{DEFAULT_BASELINE_FILENAME}" or to the .json file named next; --generate-baseline=PATH takes any name.',
    ),
    _path_option(
        "--generate-baseline-path",
        "generate_baseline_path",
        "Superseded spelling of --generate-baseline=PATH; identical behaviour, and it warns.",
    ),
    _path_option(
        "--migrate-baseline",
        "migrate_baseline_path",
        "Carry a 0.5 baseline's reviews into --generate-baseline; the original file is left untouched.",
    ),
    _option(
        "--force",
        "force_baseline_overwrite",
        is_flag=True,
        default=False,
        help="Overwrite a 0.5 baseline at the default path; without it a generate that would destroy the retreat path is refused.",
    ),
    _option(
        "--no-baseline",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default baseline file for this run.",
    ),
)

_REPORT_COMPAT_DECORATORS: tuple[ClickDecorator, ...] = (
    _ignored_path_option("--infection-report", "Path to a full Infection JSON report to ingest."),
    _ignored_path_option(
        "--mutation-baseline",
        "Path to a baseline Infection JSON report for MSI diff mode.",
    ),
    _ignored_int_option("--mutation-budget", "Maximum escaped/timed-out mutants allowed."),
    _option(
        "--diff",
        "diff_mode",
        default="",
        help="Filter findings to changed regions. Use working-tree, staged, unstaged, a base ref, or - for unified diff on stdin.",
    ),
    _option(
        "--diff-base",
        default="",
        help="The ref a diff is taken against. Canonical spelling of --diff-vs.",
    ),
    _option("--diff-vs", default="", help="Superseded spelling of --diff-base; identical behaviour."),
    _ignored_flag_option("--changed-only", "With --diff-base, compare only changed files."),
    _ignored_path_option(
        "--paths-relative-to",
        "Normalize absolute finding paths relative to this directory for reports.",
    ),
    _ignored_path_option("--history-file", "Append score trend history to this JSON file."),
    _path_option(
        "--baseline-path",
        "baseline_path",
        "Superseded spelling of --baseline; identical behaviour, and it warns.",
    ),
    _option(
        "--no-baseline",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default baseline file for this run.",
    ),
)

_ANALYSE_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    *_ANALYSIS_COMPAT_DECORATORS,
    _option(
        "--deep-scan-budget",
        default="",
        help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
    ),
    _option(
        "--exclude-rule",
        multiple=True,
        help="Do not run these comma-separated rule IDs or repeated values; the score moves with them.",
    ),
    _option(
        "--include-rule",
        multiple=True,
        help="Run only these comma-separated rule IDs or repeated values; the score moves with them.",
    ),
    _option(
        "--exclude-pillar",
        multiple=True,
        help="Do not run rules in these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        help="Run only rules in these comma-separated pillars or repeated values.",
    ),
    _option(
        "--hide-rule",
        multiple=True,
        help="Hide these comma-separated rule IDs from the report; execution and score are unchanged.",
    ),
    _option(
        "--show-rule",
        multiple=True,
        help="Show only these comma-separated rule IDs in the report; execution and score are unchanged.",
    ),
    _option(
        "--hide-pillar",
        multiple=True,
        help="Hide these comma-separated pillars from the report.",
    ),
    _option(
        "--show-pillar",
        multiple=True,
        help="Show only these comma-separated pillars in the report.",
    ),
    _option(
        "--min-severity",
        type=click.Choice([s.value for s in Severity]),
        default=None,
        help="Display only findings at or above advisory, warning, or error.",
    ),
    _option(
        "--min-confidence",
        type=click.Choice([c.value for c in Confidence]),
        default=None,
        help="Lowest confidence that reaches the exit gate: low, medium, or high. Never filters the report.",
    ),
    _option(
        "--fail-on-new",
        is_flag=True,
        default=False,
        help="Exit 1 when any finding is new against the applied baseline, whatever its severity.",
    ),
    _ignored_string_option(
        "--scan-timeout",
        "Parsed and accepted for cross-port compatibility; gruff-py enforces no scan deadline on analyse.",
        "",
    ),
    _option(
        "--diff-base",
        default="",
        help="The ref a diff is taken against. Canonical spelling of --diff-vs.",
    ),
    _option(
        "--baseline",
        "baseline",
        type=click.Path(path_type=Path),
        default=None,
        help="Apply this baseline v3 file. Canonical spelling of --baseline-path.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters.",
    ),
    _option(
        "--report-editor-link",
        type=click.Choice(["vscode", "phpstorm", "none"]),
        default="none",
        show_default=True,
        help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="advisory",
        show_default=True,
        help=(
            "Finding severity that fails the run: advisory, warning, error, or none. "
            "Gates findings only; parse errors exit 2 even with --fail-on none. "
            "Overridden by failOn.analyse in .gruff-py.yaml when --fail-on "
            "is not passed explicitly."
        ),
    ),
    _option(
        "--format",
        "output_format",
        type=click.Choice([f.value for f in OutputFormat]),
        default="text",
        show_default=True,
        help="Output format: text, json, html, markdown, github, hotspot, or sarif.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _option(
        "--strict-config",
        "strict_config",
        is_flag=True,
        default=False,
        help=("Fail on unknown rule-level config keys instead of warning and continuing with that rule's defaults."),
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(cls=_AnalyseCommand),
)

_DASHBOARD_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--deep-scan-budget",
        default="",
        help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
    ),
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters in dashboard scans.",
    ),
    _option(
        "--project-root",
        "project_root",
        type=click.Path(path_type=Path),
        default=None,
        help="Alias for --project.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--diff",
        is_flag=True,
        default=False,
        expose_value=False,
        # Keep the ratified phrase searchable on one help line for terminal users.
        help=("\b\nDiff-only dashboard scans: accepted for cross-port compatibility; not implemented in gruff-py."),
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for dashboard scans.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Initial gruff YAML or TOML config path (.yaml, .yml, or .toml).",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="none",
        show_default=True,
        help="Finding severity that fails the scan: advisory, warning, error, or none.",
    ),
    _option(
        "--scan-timeout",
        type=int,
        default=120,
        show_default=True,
        expose_value=False,
        # Keep the ratified phrase searchable on one help line for terminal users.
        help=("\b\nDashboard scan timeouts: accepted for cross-port compatibility; not implemented in gruff-py."),
    ),
    _option(
        "--port",
        type=int,
        default=8765,
        show_default=True,
        help="Port for the dashboard server.",
    ),
    _option(
        "--allow-public",
        is_flag=True,
        default=False,
        help=("Acknowledge the risk of binding the unauthenticated dashboard to a non-loopback host."),
    ),
    _option(
        "--host",
        default="127.0.0.1",
        show_default=True,
        help="Host for the dashboard server.",
    ),
    _option(
        "--project",
        "project_root",
        type=click.Path(path_type=Path),
        default=None,
        help="Initial project root for scans.",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_LIST_RULES_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--format",
        "rule_format",
        type=click.Choice(["text", "table", "json"]),
        default="table",
        show_default=True,
        help="Output format: text, table, or json.",
    ),
    _argument("rule_id", nargs=1, required=False, type=str),
    _command("list-rules"),
)

_REPORT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    *_REPORT_COMPAT_DECORATORS,
    _option(
        "--deep-scan-budget",
        default="",
        help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
    ),
    _option(
        "--exclude-rule",
        multiple=True,
        help="Do not run these comma-separated rule IDs or repeated values; the score moves with them.",
    ),
    _option(
        "--include-rule",
        multiple=True,
        help="Run only these comma-separated rule IDs or repeated values; the score moves with them.",
    ),
    _option(
        "--exclude-pillar",
        multiple=True,
        help="Do not run rules in these comma-separated pillars or repeated values.",
    ),
    _option(
        "--include-pillar",
        multiple=True,
        help="Run only rules in these comma-separated pillars or repeated values.",
    ),
    _option(
        "--min-severity",
        type=click.Choice([s.value for s in Severity]),
        default=None,
        help="Display only findings at or above advisory, warning, or error.",
    ),
    _option(
        "--baseline",
        "baseline",
        type=click.Path(path_type=Path),
        default=None,
        help="Apply this baseline v3 file. Canonical spelling of --baseline-path.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--report-interactive",
        is_flag=True,
        default=False,
        help="Render opt-in interactive HTML finding filters.",
    ),
    _option(
        "--report-editor-link",
        type=click.Choice(["vscode", "phpstorm", "none"]),
        default="none",
        show_default=True,
        help="Editor link style for HTML file:line references: vscode, phpstorm, or none.",
    ),
    _option(
        "--fail-on",
        "fail_on",
        type=click.Choice([f.value for f in FailThreshold]),
        default="none",
        show_default=True,
        help="Finding severity that fails the scan: advisory, warning, error, or none.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _option(
        "--strict-config",
        "strict_config",
        is_flag=True,
        default=False,
        help=("Fail on unknown rule-level config keys instead of warning and continuing with that rule's defaults."),
    ),
    _option(
        "--output",
        "output_path",
        type=click.Path(path_type=Path),
        help="Write the report to this file.",
    ),
    _option(
        "--format",
        "report_format",
        type=click.Choice(["html", "json"]),
        default="html",
        show_default=True,
        help="Report format: html or json.",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_SUMMARY_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--deep-scan-budget",
        default="",
        help="Override both deep-scan bounds as LINES:BYTES, or disable with off.",
    ),
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--top",
        type=int,
        default=10,
        show_default=True,
        help="How many top rules and file offenders to list.",
    ),
    _option(
        "--group-by",
        "group_by",
        type=click.Choice(["none", "rule"]),
        default="none",
        show_default=True,
        help=(
            "Group findings by an axis instead of the default digest. "
            "'rule' replaces the top-rules block with a count / rule-id / "
            "severity / confidence table."
        ),
    ),
    _option(
        "--format",
        "summary_format",
        type=click.Choice(["text", "json"]),
        default="text",
        show_default=True,
        help="Output format: text or json.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _option(
        "--strict-config",
        "strict_config",
        is_flag=True,
        default=False,
        help=("Fail on unknown rule-level config keys instead of warning and continuing with that rule's defaults."),
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command(),
)

_METRIC_CALIBRATION_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--include-ignored",
        is_flag=True,
        default=False,
        help="Scan default-ignored and .gitignore paths; configured paths.ignore still applies.",
    ),
    _option(
        "--top",
        type=int,
        default=10,
        show_default=True,
        help="How many top functions to list for each metric.",
    ),
    _option(
        "--format",
        "calibration_format",
        type=click.Choice(["text", "json"]),
        default="text",
        show_default=True,
        help="Output format: text or json.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command("metric-calibration", hidden=True),
)

_LIST_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _option("--short", is_flag=True, help="Skip describing command arguments."),
    _option(
        "--format",
        "list_format",
        type=click.Choice(["txt", "xml", "json", "md"]),
        default="txt",
        show_default=True,
        help="The output format.",
    ),
    _option("--raw", is_flag=True, help="Output raw command list."),
    _argument("namespace", required=False),
    _command("list"),
)

_HELP_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _argument("command_name", required=False),
    _command("help"),
)

_COMPLETION_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    _pass_context,
    *_GLOBAL_COMMAND_DECORATORS,
    _option("--debug", is_flag=True, help="Tail the completion debug log."),
    _argument("shell", required=False),
    _command(),
)

_INIT_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--force",
        is_flag=True,
        default=False,
        help=("Regenerate a valid .gruff-py.yaml while preserving all supported settings; comments and formatting may change."),
    ),
    _command(),
)


_CHECK_IGNORE_COMMAND_DECORATORS: tuple[ClickDecorator, ...] = (
    *_GLOBAL_COMMAND_DECORATORS,
    _option(
        "--format",
        "check_ignore_format",
        type=click.Choice(["text", "json"]),
        default="text",
        show_default=True,
        help="Output format: text or json.",
    ),
    _option(
        "--no-config",
        is_flag=True,
        default=False,
        help="Skip auto-applying the default .gruff-py.yaml file for this run.",
    ),
    _option(
        "--config",
        "config_path",
        type=click.Path(path_type=Path),
        default=None,
        help="Path to a gruff YAML or TOML config file (.yaml, .yml, or .toml).",
    ),
    _argument("paths", nargs=-1, type=click.Path()),
    _command("check-ignore"),
)
