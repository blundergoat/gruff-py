"""Shared false-positive guard for unittest subtest loops in test-quality rules.

Used by ``test-quality.loop-assertion-without-message`` so loops wrapped in ``with self.subTest(...)`` stay quiet.
Each subTest context already labels the failing iteration for the developer, making an extra assert message redundant.
"""

import ast


def is_subtest_loop(
    node: ast.For | ast.AsyncFor | ast.While,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Recognise a loop whose body gives each statement unittest case context.

    Args:
        node: Candidate loop in a unittest test method.
        fn: Owning method. Its first positional parameter names the receiver. No such parameter or a name store for it disqualifies the loop.

    Returns:
        True for a nonempty for or async-for body of with statements, each using receiver.subTest with an argument that refers to a loop target.
        Only a simple target name or a direct named element of a tuple or list target counts.
        Loops with an else block or any if or match descendant in the body return False; while loops also return False.
    """
    if isinstance(node, ast.While) or node.orelse or _contains_branch(node.body):
        return False
    parameters = [*fn.args.posonlyargs, *fn.args.args]
    if not parameters:
        return False
    receiver = parameters[0].arg
    if any(isinstance(n, ast.Name) and n.id == receiver and isinstance(n.ctx, ast.Store) for n in ast.walk(fn)):
        return False
    bound_names = _target_names(node.target)
    return bool(node.body) and all(_is_subtest_statement(statement, receiver, bound_names) for statement in node.body)


def _is_subtest_statement(statement: ast.stmt, receiver: str, bound_names: frozenset[str]) -> bool:
    """Recognize a with statement whose subTest arguments refer to a loop target.

    Args:
        statement: Loop-body statement to inspect for a matching with context.
        receiver: Name of the owning unittest method's TestCase receiver.
        bound_names: Loop-target names whose references establish case context.

    Returns:
        True when a matching subTest context argument contains a bound name; false otherwise.
    """
    if not isinstance(statement, ast.With):
        return False
    for item in statement.items:
        call = item.context_expr
        if not isinstance(call, ast.Call) or _call_name(call) != f"{receiver}.subTest":
            continue
        values = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(isinstance(n, ast.Name) and n.id in bound_names for value in values for n in ast.walk(value)):
            return True
    return False


def _target_names(target: ast.expr) -> frozenset[str]:
    """Extract names directly bound by a loop target.

    Args:
        target: Loop assignment target inspected for names used by the subtest-loop exemption.

    Returns:
        A frozen set containing the simple name or direct names from a tuple or list. Other shapes and nested unpacking contribute no names.
    """
    if isinstance(target, ast.Name):
        return frozenset({target.id})
    if isinstance(target, ast.Tuple | ast.List):
        return frozenset(elt.id for elt in target.elts if isinstance(elt, ast.Name))
    return frozenset()


def _contains_branch(statements: list[ast.stmt]) -> bool:
    """Recognize if or match nodes in supplied statements and their descendants.

    Args:
        statements: Statement roots to walk, including any nested scopes beneath them.

    Returns:
        True when a supplied statement or any descendant is an if or match node; false otherwise.
    """
    return any(isinstance(node, ast.If | ast.Match) for statement in statements for node in ast.walk(statement))


def _call_name(call: ast.Call) -> str:
    """Extract a call target's available name and attribute components.

    Args:
        call: Call whose callee syntax is read without import or runtime resolution.

    Returns:
        A dotted spelling, trailing attributes for an unsupported root, or an empty string when no components are named.
    """
    parts: list[str] = []
    node: ast.AST = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))
