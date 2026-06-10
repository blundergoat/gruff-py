"""Shared AST helpers for security-pillar rules.

Resolves dotted call targets (``pickle.loads``, ``subprocess.run``), keyword
arguments, false-literal constants, dynamic-string construction (f-strings,
``%``/``.format``, ``+`` concat), framework imports (Flask / FastAPI / Django /
SQLAlchemy / requests), and security-smell variable names.

These are intentionally conservative: false negatives (a missed exploit pattern)
are user-tunable via threshold/severity overrides; false positives erode trust
in the analyser, per `gruff-py/.goat-flow/learning-loop/footguns/compatibility.md`.
"""

import ast
import re
from collections.abc import Mapping

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
_MODULE_CONSTANT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


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


def module_string_constants(tree: ast.AST) -> dict[str, str]:
    """Return same-module ALL-CAPS string constants safe for conservative propagation.

    A name qualifies only when its single module-scope binding is one
    top-level plain assignment of a string literal. Any other module-scope
    binding - a rebind nested in a module-level ``if``/``try``/loop block,
    an import collision, a ``global`` rebind from a function body, or a
    ``del`` - disqualifies the name.

    Args:
        tree: Module AST to inspect.

    Returns:
        Mapping of single-assignment ALL-CAPS module names to string values.
    """
    if not isinstance(tree, ast.Module):
        return {}
    candidates: dict[str, str] = {}
    owner_targets: dict[str, ast.Name] = {}
    invalid: set[str] = set()
    for stmt in tree.body:
        _collect_module_constant_candidate(stmt, candidates, owner_targets, invalid)
    invalid.update(_module_scope_rebound_names(tree, owner_targets))
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            invalid.update(name for name in node.names if _is_module_constant_name(name))
        elif isinstance(node, ast.Delete):
            invalid.update(_deleted_constant_names(node.targets))
    return {
        name: value
        for name, value in candidates.items()
        if name not in invalid and _is_module_constant_name(name)
    }


def _collect_module_constant_candidate(
    stmt: ast.stmt,
    candidates: dict[str, str],
    owner_targets: dict[str, ast.Name],
    invalid: set[str],
) -> None:
    if isinstance(stmt, ast.Assign):
        _collect_plain_assign_candidate(stmt, candidates, owner_targets, invalid)
        return
    if isinstance(stmt, ast.AnnAssign | ast.AugAssign):
        name = _constant_target_name(stmt.target)
        if name is not None:
            invalid.add(name)
        return
    if isinstance(stmt, ast.Import):
        invalid.update(_constant_import_names(stmt.names))
        return
    if isinstance(stmt, ast.ImportFrom):
        invalid.update(_constant_import_names(stmt.names))
        return
    if isinstance(stmt, ast.Delete):
        invalid.update(_deleted_constant_names(stmt.targets))


def _collect_plain_assign_candidate(
    stmt: ast.Assign,
    candidates: dict[str, str],
    owner_targets: dict[str, ast.Name],
    invalid: set[str],
) -> None:
    if len(stmt.targets) != 1:
        names = (_constant_target_name(target) for target in stmt.targets)
        invalid.update(name for name in names if name is not None)
        return
    target = stmt.targets[0]
    if not isinstance(target, ast.Name) or not _is_module_constant_name(target.id):
        return
    if target.id in candidates:
        invalid.add(target.id)
        return
    if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
        candidates[target.id] = stmt.value.value
        owner_targets[target.id] = target
        return
    invalid.add(target.id)


def _module_scope_rebound_names(
    tree: ast.Module,
    owner_targets: Mapping[str, ast.Name],
) -> set[str]:
    """Return ALL-CAPS names bound at module scope outside their recording assignment.

    Covers rebinds nested in module-level blocks (``if``/``try``/``with``),
    loop targets, tuple unpacking, walrus expressions, and nested imports.
    Function and class bodies are skipped: they bind their own scopes, and
    module rebinds from inside a function require ``global``, which the
    caller handles separately.
    """
    rebound: set[str] = set()
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        if isinstance(node, ast.Name):
            if (
                isinstance(node.ctx, ast.Store)
                and _is_module_constant_name(node.id)
                and node is not owner_targets.get(node.id)
            ):
                rebound.add(node.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            rebound.update(_constant_import_names(node.names))
        stack.extend(ast.iter_child_nodes(node))
    return rebound


def _constant_target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name) and _is_module_constant_name(target.id):
        return target.id
    return None


def _constant_import_names(aliases: list[ast.alias]) -> set[str]:
    names: set[str] = set()
    for alias in aliases:
        assigned = alias.asname or alias.name.split(".", 1)[0]
        if _is_module_constant_name(assigned):
            names.add(assigned)
    return names


def _deleted_constant_names(targets: list[ast.expr]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        name = _constant_target_name(target)
        if name is not None:
            names.add(name)
    return names


def _is_module_constant_name(name: str) -> bool:
    return bool(_MODULE_CONSTANT_RE.fullmatch(name))


def is_fixed_string_expression(node: ast.expr, constants: Mapping[str, str]) -> bool:
    """Return whether *node* resolves only to same-module fixed string material.

    Args:
        node: Expression to inspect.
        constants: Same-module string constants from :func:`module_string_constants`.

    Returns:
        True when the expression is fully fixed at import time.
    """
    return _fixed_string_value(node, constants) is not None


def fixed_string_fragments(node: ast.expr, constants: Mapping[str, str]) -> tuple[str, ...]:
    """Return fixed string fragments visible inside *node*.

    Args:
        node: Expression to inspect.
        constants: Same-module string constants from :func:`module_string_constants`.

    Returns:
        Literal and constant string fragments found in stable traversal order.
    """
    fragments: list[str] = []
    _collect_fixed_string_fragments(node, constants, fragments)
    return tuple(fragments)


def _fixed_string_value(node: ast.expr, constants: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return _fixed_joined_string_value(node, constants)
    if isinstance(node, ast.BinOp):
        return _fixed_binop_string_value(node, constants)
    if _is_format_call(node):
        return _fixed_format_call_value(node, constants)
    return None


def _fixed_joined_string_value(node: ast.JoinedStr, constants: Mapping[str, str]) -> str | None:
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
            continue
        if isinstance(value, ast.FormattedValue):
            if value.conversion != -1 or value.format_spec is not None:
                return None
            fixed = _fixed_string_value(value.value, constants)
            if fixed is None:
                return None
            parts.append(fixed)
            continue
        return None
    return "".join(parts)


def _fixed_binop_string_value(node: ast.BinOp, constants: Mapping[str, str]) -> str | None:
    left = _fixed_string_value(node.left, constants)
    if left is None:
        return None
    if isinstance(node.op, ast.Add):
        right = _fixed_string_value(node.right, constants)
        return None if right is None else left + right
    if isinstance(node.op, ast.Mod):
        right_values = _fixed_format_values(node.right, constants)
        return None if right_values is None else left + "".join(right_values)
    return None


def _fixed_format_call_value(node: ast.expr, constants: Mapping[str, str]) -> str | None:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return None
    receiver = _fixed_string_value(node.func.value, constants)
    if receiver is None:
        return None
    values: list[str] = []
    for arg in node.args:
        fixed = _fixed_string_value(arg, constants)
        if fixed is None:
            return None
        values.append(fixed)
    for keyword in node.keywords:
        if keyword.arg is None:
            return None
        fixed = _fixed_string_value(keyword.value, constants)
        if fixed is None:
            return None
        values.append(fixed)
    return receiver + "".join(values)


def _fixed_format_values(node: ast.expr, constants: Mapping[str, str]) -> list[str] | None:
    if isinstance(node, ast.Tuple):
        values: list[str] = []
        for item in node.elts:
            fixed = _fixed_string_value(item, constants)
            if fixed is None:
                return None
            values.append(fixed)
        return values
    fixed = _fixed_string_value(node, constants)
    return None if fixed is None else [fixed]


def _collect_fixed_string_fragments(
    node: ast.expr,
    constants: Mapping[str, str],
    fragments: list[str],
) -> None:
    """Collect only compile-time string fragments from dynamic string builders.

    The branch structure mirrors Python's common string-building AST shapes:
    f-strings, `+` concatenation, and `.format(...)`. Runtime holes are visited
    only to recover nested fixed fragments; callers use the resulting keyword
    evidence without treating dynamic values as safe.
    """
    fixed = _fixed_string_value(node, constants)
    if fixed is not None:
        fragments.append(fixed)
        return
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                fragments.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                _collect_fixed_string_fragments(value.value, constants, fragments)
        return
    if isinstance(node, ast.BinOp):
        _collect_fixed_string_fragments(node.left, constants, fragments)
        _collect_fixed_string_fragments(node.right, constants, fragments)
        return
    if (
        _is_format_call(node)
        and isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    ):
        _collect_fixed_string_fragments(node.func.value, constants, fragments)
        for arg in node.args:
            _collect_fixed_string_fragments(arg, constants, fragments)
        for keyword in node.keywords:
            _collect_fixed_string_fragments(keyword.value, constants, fragments)


def is_dynamic_string(node: ast.expr) -> bool:
    """Return whether an expression builds a string from runtime values.

    These are the four shapes that produce strings whose contents depend on
    runtime values - i.e. the classic SQL-concat / shell-concat anti-patterns.

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
