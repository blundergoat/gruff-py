"""Shared AST helpers for security-pillar rules.

Resolves dotted call targets (``pickle.loads``, ``subprocess.run``), keyword
arguments, false-literal constants, dynamic-string construction (f-strings,
``%``/``.format``, ``+`` concat), framework imports (Flask / FastAPI / Django /
SQLAlchemy / requests), and security-smell variable names.

These are intentionally conservative: false negatives (a missed exploit pattern)
are user-tunable via threshold/severity overrides; false positives erode trust
in the analyser, per `gruff-py/.goat-flow/footguns/compatibility.md`.
"""

import ast

# Identifier substrings that suggest a name carries security-sensitive data.
_SECURITY_SMELL_TOKENS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "private_key",
        "session",
        "signature",
        "digest",
        "hmac",
        "otp",
        "nonce",
        "salt",
    }
)

# Imports that mark the file as operating in a given framework's context.
# The values are the framework labels returned by frameworks_in_use().
_FRAMEWORK_IMPORTS: dict[str, str] = {
    "flask": "flask",
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "django": "django",
    "rest_framework": "django",
    "quart": "flask",
    "sqlalchemy": "sqlalchemy",
    "requests": "requests",
}


def call_target_name(call: ast.Call) -> str | None:
    """Return the dotted name of *call*'s target, or None for dynamic calls.

    Examples:

    - ``eval(...)`` → ``"eval"``
    - ``pickle.loads(...)`` → ``"pickle.loads"``
    - ``self.method(...)`` → ``"self.method"``
    - ``urllib.request.urlopen(...)`` → ``"urllib.request.urlopen"``
    - ``func_var(...)`` (where ``func_var`` is a local) → ``"func_var"``
    - ``(a or b)(...)`` → ``None``
    """
    return _resolve_name(call.func)


def _resolve_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _resolve_name(node.value)
        if prefix is None:
            return None
        return f"{prefix}.{node.attr}"
    return None


def call_keyword(call: ast.Call, name: str) -> ast.expr | None:
    """Return the value expression for keyword argument *name*, if present."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_false_constant(node: ast.expr) -> bool:
    """True when *node* is the literal ``False`` or ``0``."""
    if not isinstance(node, ast.Constant):
        return False
    return node.value is False or node.value == 0


def is_string_literal(node: ast.expr) -> bool:
    """True when *node* is a pure ``str`` literal (no f-string interpolation)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.expr) -> bool:
    """True when *node* is an f-string, ``%`` format, ``.format`` call, or ``str + str`` concat.

    These are the four shapes that produce strings whose contents depend on
    runtime values — i.e. the classic SQL-concat / shell-concat anti-patterns.
    """
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add) and (_produces_str(node.left) or _produces_str(node.right)):
            return True
        if isinstance(node.op, ast.Mod) and _produces_str(node.left):
            return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _produces_str(node: ast.expr) -> bool:
    """Best-effort: does *node* yield a str at runtime?"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return _produces_str(node.left) or _produces_str(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in {"format", "join"}
    return False


def frameworks_in_use(tree: ast.AST) -> frozenset[str]:
    """Return the set of frameworks the file imports (best-effort, based on top-level imports).

    Used to scope rules like ``security.header-injection`` (Flask/FastAPI/Django)
    so they only fire inside files that actually use the framework.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    detected: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0].lower()
                if root in _FRAMEWORK_IMPORTS:
                    detected.add(_FRAMEWORK_IMPORTS[root])
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            root = node.module.split(".")[0].lower()
            if root in _FRAMEWORK_IMPORTS:
                detected.add(_FRAMEWORK_IMPORTS[root])
    return frozenset(detected)


def name_smells_security(name: str) -> bool:
    """True if *name* suggests it holds security-sensitive material.

    Substring match against a curated token list (``password``, ``token``,
    ``secret``, ``api_key``, ``auth``, ``signature``, ``hmac``, ``otp``, etc.).
    Matches on lowercased name.
    """
    lowered = name.lower()
    return any(token in lowered for token in _SECURITY_SMELL_TOKENS)


def body_is_pass_or_ellipsis(body: list[ast.stmt]) -> bool:
    """True if *body* is exactly ``pass`` or ``...`` with no other statements.

    Used by ``security.silent-except`` to recognise empty except handlers.
    """
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def exception_handler_logs(handler: ast.ExceptHandler) -> bool:
    """True if *handler*'s body contains any call that looks like logging.

    Conservative: only matches dotted calls whose target's leaf is one of
    ``log``, ``debug``, ``info``, ``warning``, ``error``, ``critical``,
    ``exception``, ``logger``, or ``logging``. Used to suppress
    ``security.silent-except`` when the user is at least logging.
    """
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        target = call_target_name(node)
        if target is None:
            continue
        leaf = target.split(".")[-1]
        if leaf in {
            "log",
            "debug",
            "info",
            "warning",
            "error",
            "critical",
            "exception",
        }:
            return True
        if leaf in {"print"}:
            # `print` is a weak but valid signal that the exception isn't swallowed silently.
            return True
    return False
