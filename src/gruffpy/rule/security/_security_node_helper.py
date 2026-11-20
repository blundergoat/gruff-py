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
_LOGGING_LEAVES: frozenset[str] = frozenset({"log", "debug", "info", "warning", "error", "critical", "exception", "print"})
_MODULE_CONSTANT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def call_target_name(call: ast.Call) -> str | None:
    """Return the spelling of a name-based call target without resolving runtime bindings.

    Args:
        call: Call expression to inspect.

    Returns:
        A bare name or a dotted attribute chain rooted in a name, or None for other callee expressions.
    """
    return _resolve_name(call.func)


def _resolve_name(node: ast.AST) -> str | None:
    """Resolve a syntactic chain of names and attributes to dotted text.

    Args:
        node: Expression whose names and attribute receivers are inspected without resolving bindings.

    Returns:
        Bare name or dotted attribute chain. None when the expression or any attribute receiver has an unsupported shape.
    """
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
        call: Call whose explicitly named keyword arguments are searched. Keyword unpacking is skipped.
        name: Keyword name to find.

    Returns:
        Keyword value expression, or None when absent.
    """
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_false_constant(node: ast.expr) -> bool:
    """Return whether an expression is a constant whose value is False or equals zero.

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
        node: Parsed expression checked for a string constant at its root.

    Returns:
        True for a string-valued AST constant, including an empty string. False for all other expressions.
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
    return {name: value for name, value in candidates.items() if name not in invalid and _is_module_constant_name(name)}


def _collect_module_constant_candidate(
    stmt: ast.stmt,
    candidates: dict[str, str],
    owner_targets: dict[str, ast.Name],
    invalid: set[str],
) -> None:
    """Record candidate string constants or disqualifying top-level bindings.

    Args:
        stmt: Direct module-body statement checked for supported assignment, import or deletion forms.
        candidates: Candidate names and string values, mutated when a qualifying assignment is found.
        owner_targets: Candidate names and their original AST target objects, mutated alongside candidates.
        invalid: Names disqualified by encountered bindings, extended in place.

    Returns:
        None; candidate records and disqualified names are updated in place.
    """
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
    """Record a single ALL-CAPS string assignment or invalidate its name.

    Args:
        stmt: Plain assignment checked for one direct ALL-CAPS target and a string literal value.
        candidates: Recorded candidate values, extended for a qualifying name not previously recorded.
        owner_targets: Original AST targets, extended with the qualifying assignment's target object.
        invalid: Names disqualified by repeated or unsupported assignments, extended in place.

    Returns:
        None; candidate records and disqualified names are updated in place.
    """
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
    """Find supported ALL-CAPS store and import bindings outside recorded candidate targets.

    Function, class and lambda subtrees are skipped; the caller checks global declarations separately.

    Args:
        tree: Module scanned for bindings in its body, including nested blocks and comprehension targets.
        owner_targets: Original candidate target objects exempted by identity from the rebind scan.

    Returns:
        ALL-CAPS names encountered in other supported store or import bindings; empty when none are found.
    """
    rebound: set[str] = set()
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Store) and _is_module_constant_name(node.id) and node is not owner_targets.get(node.id):
                rebound.add(node.id)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            rebound.update(_constant_import_names(node.names))
        stack.extend(ast.iter_child_nodes(node))
    return rebound


def _constant_target_name(target: ast.AST) -> str | None:
    """Recognize a direct ALL-CAPS assignment target.

    Args:
        target: Target expression checked as a single name rather than unpacked recursively.

    Returns:
        The target name when it matches the constant spelling, or None for other targets.
    """
    if isinstance(target, ast.Name) and _is_module_constant_name(target.id):
        return target.id
    return None


def _constant_import_names(aliases: list[ast.alias]) -> set[str]:
    """Collect ALL-CAPS names bound by import aliases.

    Args:
        aliases: Import aliases whose explicit alias or first module component supplies the bound spelling.

    Returns:
        Bound names matching the constant spelling, or an empty set when no alias qualifies.
    """
    names: set[str] = set()
    for alias in aliases:
        assigned = alias.asname or alias.name.split(".", 1)[0]
        if _is_module_constant_name(assigned):
            names.add(assigned)
    return names


def _deleted_constant_names(targets: list[ast.expr]) -> set[str]:
    """Collect directly named ALL-CAPS deletion targets.

    Args:
        targets: Deletion targets checked individually without unpacking nested target containers.

    Returns:
        Qualifying direct names, or an empty set when no target matches.
    """
    names: set[str] = set()
    for target in targets:
        name = _constant_target_name(target)
        if name is not None:
            names.add(name)
    return names


def _is_module_constant_name(name: str) -> bool:
    """Check a name against the supported ALL-CAPS constant spelling.

    Args:
        name: Identifier spelling tested from start to end against the constant-name pattern.

    Returns:
        True for a name starting with an ASCII uppercase letter, with any remaining characters limited to A-Z, 0-9 and underscore. False otherwise.
    """
    return bool(_MODULE_CONSTANT_RE.fullmatch(name))


def is_fixed_string_expression(node: ast.expr, constants: Mapping[str, str]) -> bool:
    """Recognize supported expressions composed of fixed string material.

    Args:
        node: Expression to inspect.
        constants: Same-module string constants from module_string_constants.

    Returns:
        True when every required piece resolves to fixed string material, including empty strings. False for unsupported or unresolved pieces.
    """
    return _fixed_string_value(node, constants) is not None


def _fixed_string_value(node: ast.expr, constants: Mapping[str, str]) -> str | None:
    """Collect fixed string material from supported expression shapes.

    This supports fixedness checks; formatted material is not an evaluated Python formatting result.

    Args:
        node: Expression inspected for literals, known names or supported string-building syntax.
        constants: Read-only mapping of same-module names to known string values.

    Returns:
        Collected string material, including an empty string, or None when any required part is unresolved.
    """
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
    """Collect f-string material when each interpolated value is a fixed string.

    Args:
        node: Joined string whose literal and interpolated parts are checked in order.
        constants: Known string values used to resolve names in interpolated expressions.

    Returns:
        Combined fixed material, possibly empty; None for conversions, format specifications or unresolved parts.
    """
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
    """Collect fixed string material from addition or percent-formatting syntax.

    Percent formatting combines template and argument material without evaluating formatting directives.

    Args:
        node: Binary expression whose left side and supported right-side values must resolve to strings.
        constants: Known string values used while checking both operands.

    Returns:
        Combined fixed material, possibly empty; None for another operator or an unresolved operand.
    """
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
    """Collect fixed receiver and argument material from a format call.

    The returned material establishes fixedness without executing the receiver's formatting directives.

    Args:
        node: Expression checked for an attribute call named format with supported fixed arguments.
        constants: Known string values used to resolve the receiver and argument expressions.

    Returns:
        Receiver material followed by argument material, possibly empty. None if the expression has another shape,
        a required part is unresolved, or the call expands keyword arguments.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"):
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
    """Collect fixed string values for a percent-formatting operand.

    Args:
        node: Single operand or tuple whose items are checked as fixed strings.
        constants: Known string values used to resolve the operand or tuple items.

    Returns:
        Fixed values in operand order, possibly an empty list for an empty tuple; None if a value is unresolved.
    """
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


def is_dynamic_string(node: ast.expr) -> bool:
    """Recognize string-building syntax that may contain runtime values.

    This heuristic does not prove string types or exclude constant concatenation and formatting.

    Args:
        node: Expression to inspect.

    Returns:
        True for interpolated f-strings, string-like addition or percent formatting, or calls to a format attribute. False otherwise.
    """
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _is_dynamic_string_binop(node)
    return _is_format_call(node)


def _is_str_producer(node: ast.expr) -> bool:
    """Recognize syntax that may produce a string without resolving runtime types.

    Args:
        node: Expression checked for string literals, f-strings, supported binary operations or calls to format or join attributes.

    Returns:
        True when a string-producing syntax heuristic matches; False otherwise, without resolving runtime types.
    """
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
    """Recognize addition and percent-formatting shapes involving string syntax.

    Args:
        node: Binary expression checked for addition with a string-like side or percent formatting with a string-like left side.

    Returns:
        True when the syntax heuristic matches; False for unsupported operators or operand shapes.
    """
    if isinstance(node.op, ast.Add):
        return _is_str_producer(node.left) or _is_str_producer(node.right)
    return isinstance(node.op, ast.Mod) and _is_str_producer(node.left)


def _is_format_call(node: ast.expr) -> bool:
    """Recognize an attribute call whose terminal method name is format.

    Args:
        node: Expression checked by call and attribute shape without resolving its receiver type.

    Returns:
        True for a call to an attribute named format; False for other expressions.
    """
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def frameworks_in_use(tree: ast.AST) -> frozenset[str]:
    """Infer framework labels from the module's import spellings.

    Rules use these import labels to limit framework-specific checks to matching files.

    Args:
        tree: Module AST to inspect.

    Returns:
        Labels from direct module-body imports; empty for non-module input or when no recognized import is found.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    detected: set[str] = set()
    for node in tree.body:
        detected.update(_frameworks_for_import(node))
    return frozenset(detected)


def imported_module_names(tree: ast.AST) -> frozenset[str]:
    """Collect names bound by imports anywhere in a module, including imports inside handlers.

    Request checks use these bindings to see whether a dotted reference starts with an imported name.
    For example, import flask binds flask, import flask as f binds f, import urllib.request binds urllib, and from a import b binds b.

    Args:
        tree: Module AST to inspect.

    Returns:
        Names bound by import statements. Empty for a non-module tree or when no import supplies an explicit name.
    """
    if not isinstance(tree, ast.Module):
        return frozenset()
    bound: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        for alias in node.names:
            # A wildcard import can bind names this analyser cannot enumerate.
            if alias.name == "*":
                continue
            bound.add(alias.asname or alias.name.split(".", 1)[0])
    return frozenset(bound)


def _frameworks_for_import(node: ast.stmt) -> set[str]:
    """Map a supported import statement to recognized framework labels.

    Args:
        node: Statement whose imported module roots are matched against the framework table.

    Returns:
        Recognized framework labels, or an empty set for other statements and unrecognized roots.
    """
    if isinstance(node, ast.Import):
        return {_framework_for_name(alias.name) for alias in node.names} - {""}
    if isinstance(node, ast.ImportFrom) and node.module is not None:
        framework = _framework_for_name(node.module)
        return {framework} if framework else set()
    return set()


def _framework_for_name(name: str) -> str:
    """Map an imported module root to its framework label.

    Args:
        name: Imported dotted name whose first component is lowercased for the lookup.

    Returns:
        The recognized framework label, or an empty string when the root is not in the table.
    """
    root = name.split(".")[0].lower()
    return _FRAMEWORK_IMPORTS.get(root, "")


def has_security_smell(name: str) -> bool:
    """Match identifier substrings against the curated security-sensitive token set, ignoring case.

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
    """Detect logging-like call spellings anywhere in an exception handler's AST subtree.

    Args:
        handler: Exception handler to inspect.

    Returns:
        True if a call anywhere in the handler subtree has a recognized final name on a bare name or a name-rooted attribute chain. False otherwise.
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
    """Recognize a logging-like terminal call name.

    Args:
        target: Dotted call spelling whose final component is compared with the logging-name set.

    Returns:
        True when the final spelling is recognized; False otherwise, without resolving the callable.
    """
    return target.split(".")[-1] in _LOGGING_LEAVES
