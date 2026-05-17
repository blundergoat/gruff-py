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
_LOGGING_LEAVES: frozenset[str] = frozenset(
    {"log", "debug", "info", "warning", "error", "critical", "exception", "print"}
)


def call_target_name(call: ast.Call) -> str | None:
    """Return the dotted name of a call target, or None for dynamic calls.

    Examples:

    - ``eval(...)`` → ``"eval"``
    - ``pickle.loads(...)`` → ``"pickle.loads"``
    - ``self.method(...)`` → ``"self.method"``
    - ``urllib.request.urlopen(...)`` → ``"urllib.request.urlopen"``
    - ``func_var(...)`` (where ``func_var`` is a local) → ``"func_var"``
    - ``(a or b)(...)`` → ``None``

    Args:
        call: Call expression to inspect.

    Returns:
        Dotted target name, or None when the callee is dynamic.
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
    """Return the value expression for a keyword argument.

    Args:
        call: Call expression to inspect.
        name: Keyword name to find.

    Returns:
        Keyword value expression, or None when absent.
    """
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_false_constant(node: ast.expr) -> bool:
    """Return whether an expression is the literal ``False`` or ``0``.

    Args:
        node: Expression to inspect.

    Returns:
        True when the expression is a false-like constant.
    """
    if not isinstance(node, ast.Constant):
        return False
    return node.value is False or node.value == 0


def is_string_literal(node: ast.expr) -> bool:
    """Return whether an expression is a pure string literal.

    Args:
        node: Expression to inspect.

    Returns:
        True for plain string constants without interpolation.
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.expr) -> bool:
    """Return whether an expression builds a string from runtime values.

    These are the four shapes that produce strings whose contents depend on
    runtime values — i.e. the classic SQL-concat / shell-concat anti-patterns.

    Args:
        node: Expression to inspect.

    Returns:
        True for f-strings, ``%`` formatting, ``.format``, or string concatenation.
    """
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _is_dynamic_string_binop(node)
    return _is_format_call(node)


def _is_str_producer(node: ast.expr) -> bool:
    """Best-effort: does *node* yield a str at runtime?"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return _is_str_producer(node.left) or _is_str_producer(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr in {"format", "join"}
    return False


def _is_dynamic_string_binop(node: ast.BinOp) -> bool:
    if isinstance(node.op, ast.Add):
        return _is_str_producer(node.left) or _is_str_producer(node.right)
    return isinstance(node.op, ast.Mod) and _is_str_producer(node.left)


def _is_format_call(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def frameworks_in_use(tree: ast.AST) -> frozenset[str]:
    """Return frameworks imported by a module.

    Used to scope rules like ``security.header-injection`` (Flask/FastAPI/Django)
    so they only fire inside files that actually use the framework.

    Args:
        tree: Module AST to inspect.

    Returns:
        Framework labels detected from top-level imports.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    detected: set[str] = set()
    for node in tree.body:
        detected.update(_frameworks_for_import(node))
    return frozenset(detected)


def _frameworks_for_import(node: ast.stmt) -> set[str]:
    if isinstance(node, ast.Import):
        return {_framework_for_name(alias.name) for alias in node.names} - {""}
    if isinstance(node, ast.ImportFrom) and node.module is not None:
        framework = _framework_for_name(node.module)
        return {framework} if framework else set()
    return set()


def _framework_for_name(name: str) -> str:
    root = name.split(".")[0].lower()
    return _FRAMEWORK_IMPORTS.get(root, "")


def has_security_smell(name: str) -> bool:
    """Return whether a name suggests security-sensitive material.

    Substring match against a curated token list (``password``, ``token``,
    ``secret``, ``api_key``, ``auth``, ``signature``, ``hmac``, ``otp``, etc.).
    Matches on lowercased name.

    Args:
        name: Identifier to inspect.

    Returns:
        True when the lowercased name contains a security-sensitive token.
    """
    lowered = name.lower()
    return any(token in lowered for token in _SECURITY_SMELL_TOKENS)


def is_pass_or_ellipsis_body(body: list[ast.stmt]) -> bool:
    """Return whether a body is exactly ``pass`` or ``...``.

    Used by ``security.silent-except`` to recognise empty except handlers.

    Args:
        body: Statement body to inspect.

    Returns:
        True when the body has one pass or ellipsis-like expression.
    """
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def does_exception_handler_log(handler: ast.ExceptHandler) -> bool:
    """Return whether an exception handler logs or prints.

    Args:
        handler: Exception handler to inspect.

    Returns:
        True when the body contains logging-like calls.
    """
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        target = call_target_name(node)
        if target is None:
            continue
        if _is_logging_leaf(target):
            return True
    return False


def _is_logging_leaf(target: str) -> bool:
    return target.split(".")[-1] in _LOGGING_LEAVES
