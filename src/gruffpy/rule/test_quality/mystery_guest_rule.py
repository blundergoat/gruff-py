"""``test-quality.mystery-guest`` - test depends on opaque external state.

Heuristic: the test makes a call that performs network, filesystem, mail, or FTP
I/O when it runs - ``requests.get``, ``urllib.request.urlopen``,
``socket.create_connection``, a request method on a session the test opened, or
a bare ``open(...)`` - without a fixture that makes it hermetic. Constructors
that perform no I/O, ``open`` in a test that takes a temporary-directory
fixture, calls on a parameter that shadows a module name, and assertions on
mocks are not guests. Tests that pull from real external sources are
non-hermetic and slow.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    is_assertion_call,
    test_functions,
    walk_test_body,
)

_HTTP_VERBS: tuple[str, ...] = ("get", "post", "put", "delete", "head", "patch", "options", "request")
# Calls that reach the network, a mail server, or an FTP server as soon as they run; constructors such as
# ``requests.Request`` or ``requests.cookies.RequestsCookieJar`` perform no I/O and are not listed.
_EFFECTFUL_CALLS: frozenset[str] = frozenset(
    {
        *(f"requests.{verb}" for verb in _HTTP_VERBS),
        *(f"httpx.{verb}" for verb in (*_HTTP_VERBS, "stream")),
        "aiohttp.request",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "socket.socket",
        "socket.create_connection",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getaddrinfo",
        "ftplib.FTP",
        "ftplib.FTP_TLS",
        "smtplib.SMTP",
        "smtplib.SMTP_SSL",
    }
)
# A client these construct sends its request methods over the network, like the module-level helpers.
_CLIENT_CONSTRUCTORS: frozenset[str] = frozenset(
    {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "urllib3.PoolManager"}
)
_CLIENT_REQUEST_METHODS: frozenset[str] = frozenset({*_HTTP_VERBS, "send", "stream", "urlopen"})
_MYSTERY_LEAVES: frozenset[str] = frozenset({"open", "popen"})
# These pytest fixtures hand a test a private, disposable directory, so opening files is hermetic there.
_TEMPORARY_DIRECTORY_FIXTURES: frozenset[str] = frozenset({"tmp_path", "tmpdir", "tmp_path_factory", "tmpdir_factory", "pytester", "testdir"})


class MysteryGuestRule(Rule):
    """Detect tests that call network, filesystem, or other I/O without a fixture wrapping them."""

    ID = "test-quality.mystery-guest"

    def definition(self) -> RuleDefinition:
        """Describe the mystery-guest rule as a medium-confidence advisory.

        Medium confidence: the curated I/O vocabulary (network + filesystem
        leaves) catches the common cases, but legitimate fixture-style
        ``open(...)`` on a ``tmp_path`` will also fire.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Mystery guest in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests calling external I/O leaves (``open``, ``requests.*``, ``socket.*``, etc.).

        Stops at the first matching call per test; the heuristic combines a
        prefix set (``requests``, ``urllib``, ``urllib3``, ``socket``,
        ``httpx``, ``aiohttp``, ``ftplib``, ``smtplib``) with leaf names
        (``open``, ``popen``).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per test that reaches into external state, with the
            offending target captured in metadata.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            target_found = _find_mystery_target(fn)
            if target_found is None:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Test {symbol!r} touches external state via `{target_found}` - non-hermetic dependency."),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Mock the I/O boundary or use a tmp_path fixture for filesystem interactions."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target_found},
                ),
            )
        return findings


def _find_mystery_target(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the first call in a test that performs I/O without a hermetic fixture.

    Args:
        fn: Collected test function to inspect.

    Returns:
        The effectful call's dotted target, or ``None`` when the test touches no external state.
    """
    parameters = _parameter_names(fn)
    has_temporary_directory = not parameters.isdisjoint(_TEMPORARY_DIRECTORY_FIXTURES)
    clients = _client_bindings(fn)
    # Calls are judged in body order, so the reported target is the first effectful one.
    for node in walk_test_body(fn):
        # Only a call can perform I/O, and an assertion on a mock records an expectation instead.
        if not isinstance(node, ast.Call) or is_assertion_call(node):
            continue
        target = _effectful_target(node, parameters, clients, has_temporary_directory)
        # The first call that reaches external state is the guest the test depends on.
        if target is not None:
            return target
    return None


def _effectful_target(
    call: ast.Call,
    parameters: frozenset[str],
    clients: frozenset[str],
    has_temporary_directory: bool,
) -> str | None:
    """Return a call's dotted target when running it performs external I/O.

    Args:
        call: Call expression inside a test body.
        parameters: Names the test's signature binds; a module-named parameter shadows the module.
        clients: Local names bound to a network client the test constructed.
        has_temporary_directory: Whether the test takes a temporary-directory fixture.

    Returns:
        The dotted target, or ``None`` for constructors, shadowed names, and hermetic file access.
    """
    # ``requests.Session().get(...)`` sends a request from a client built in the same expression.
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call) and call.func.attr in _CLIENT_REQUEST_METHODS:
        constructor = call_target_name(call.func.value)
        return f"{constructor}().{call.func.attr}" if constructor in _CLIENT_CONSTRUCTORS else None
    target = call_target_name(call)
    # A dynamic callee or a parameter named like a module (a mocked ``socket`` fixture) is not the module.
    if target is None or target.split(".")[0] in parameters:
        return None
    # Opening a file is hermetic when the test owns a disposable directory to open it in.
    if target in _MYSTERY_LEAVES:
        return None if has_temporary_directory else target
    root, _, method = target.partition(".")
    is_client_request = root in clients and method in _CLIENT_REQUEST_METHODS
    return target if target in _EFFECTFUL_CALLS or is_client_request else None


def _parameter_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Return every name a test's signature binds.

    Args:
        fn: Test function whose parameters are read.

    Returns:
        Positional, keyword-only, and variadic parameter names.
    """
    arguments = fn.args
    named = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    variadic = [argument for argument in (arguments.vararg, arguments.kwarg) if argument is not None]
    return frozenset(argument.arg for argument in (*named, *variadic))


def _client_bindings(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Return local names a test binds to a network client it constructs.

    Args:
        fn: Test function whose assignments and ``with`` statements are read.

    Returns:
        Names such as ``session`` in ``session = requests.Session()`` or ``with httpx.Client() as session``.
    """
    names: set[str] = set()
    # A client can be bound by assignment or as the target of a ``with`` block.
    for node in walk_test_body(fn):
        # ``session = requests.Session()`` binds every simple name on the left.
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and call_target_name(node.value) in _CLIENT_CONSTRUCTORS:
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        # ``with httpx.Client() as session`` binds the ``as`` name.
        if isinstance(node, ast.With | ast.AsyncWith):
            names.update(
                item.optional_vars.id
                for item in node.items
                if isinstance(item.context_expr, ast.Call)
                and call_target_name(item.context_expr) in _CLIENT_CONSTRUCTORS
                and isinstance(item.optional_vars, ast.Name)
            )
    return frozenset(names)
