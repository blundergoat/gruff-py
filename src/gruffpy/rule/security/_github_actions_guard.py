"""Bounded source ownership and event proof for the existing workflow secret sink."""

import json
import re
from dataclasses import dataclass, field

_ENTRY = re.compile(r"""^(?:([A-Za-z0-9_.-]+)|'([^']+)'|"([^"\\]+)"|(<<)):\s*(.*)$""")
_ITEM = re.compile(r"^-(?: +|$)")
_ALIAS = re.compile(r"(?:^|\s)[&*][A-Za-z0-9_-]+")
_SCALAR = re.compile(r"^[|>](?:[+-]?\d*|\d*[+-]?)$")
_QUOTE = re.compile(r"""^(?:'(?:[^']|'')*'|"(?:[^"\\]|\\.)*")""")
_TOKEN = re.compile(r"^(?:\s+|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*|==|!=|&&|\|\||[!()])")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


@dataclass
class _GuardNode:
    """Own mapping/list entry with inclusive source range and direct children."""

    key: str = ""
    content: str = ""
    indent: int = -1
    start: int = 1
    end: int = 1
    is_item: bool = False
    children: list["_GuardNode"] = field(default_factory=list)

    def child(self, key: str) -> "_GuardNode | None":
        """Find a direct child without letting nested keys supply a guard.

        Args:
            key: Mapping key to find among this node's direct children.

        Returns:
            The matching child, or None when the key is absent.
        """
        return next((node for node in self.children if not node.is_item and node.key == key), None)


def unreachable_secret_lines(source: str) -> set[int]:
    """Prove only own job/step guards false for the detector's current PR event.

    Args:
        source: Complete workflow text used to establish ownership and event guards.

    Returns:
        One-based source lines unreachable for pull_request_target; ambiguous ownership supplies none.
    """
    blocked: set[int] = set()
    root = _ownership(source)
    jobs = root.child("jobs") if root else None
    if jobs is None or jobs.content:
        return blocked
    for job in jobs.children:
        if job.is_item or job.content:
            continue
        _mark_if_rejected(job, blocked)
        steps = job.child("steps")
        if steps is None or steps.content:
            continue
        for step in steps.children:
            if step.is_item:
                _mark_if_rejected(step, blocked)
    return blocked


def _mark_if_rejected(node: _GuardNode, blocked: set[int]) -> None:
    """Late guards apply to earlier references within the same inclusive scope."""
    guard = node.child("if")
    if guard and _event_is_true(guard.content, "pull_request_target") is False:
        blocked.update(range(node.start, node.end + 1))


def _yaml_text(raw: str) -> str | None:
    """Preserve quoted hashes; unmatched scalar quotes cannot prove ownership."""
    index = 0
    while index < len(raw):
        if raw[index] in "'\"":
            quoted = _QUOTE.match(raw[index:])
            if not quoted:
                return None
            index += len(quoted[0])
            continue
        if raw[index] == "#" and (index == 0 or raw[index - 1].isspace()):
            return raw[:index].strip()
        index += 1
    return raw.strip()


def _ownership(source: str) -> _GuardNode | None:
    """Complete all ranges before proof; ambiguous structure retains all warnings."""
    lines = source.split("\n")
    root = _GuardNode(end=len(lines))
    stack = [root]
    scalar_indent = -1
    for index, raw in enumerate(lines):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if scalar_indent >= 0 and indent > scalar_indent:
            continue
        scalar_indent = -1
        if raw[indent:].startswith("\t"):
            return None
        text = _yaml_text(raw)
        if text is None:
            return None
        match = _ITEM.match(text)
        prefix = match[0] if match else ""
        parent = _parent(stack, indent, index, prefix, len(lines))
        if parent is None:
            return None
        node = _entry(parent, text, prefix, _GuardNode(indent=indent, start=index + 1, end=len(lines)))
        if node is None:
            return None
        if node is not parent:
            stack.append(node)
        if _SCALAR.fullmatch(node.content):
            scalar_indent = node.indent
    return root


def _parent(stack: list[_GuardNode], indent: int, index: int, prefix: str, total: int) -> _GuardNode | None:
    """Close siblings before attaching a list item so guards cannot leak across steps."""
    while len(stack) > 1 and stack[-1].indent >= indent:
        stack.pop().end = index
    parent = stack[-1]
    if parent.content or any(child.is_item != bool(prefix) for child in parent.children):
        return None
    if not prefix:
        return parent
    step = _GuardNode(indent=indent, start=index + 1, end=total, is_item=True)
    parent.children.append(step)
    stack.append(step)
    return step


def _entry(parent: _GuardNode, text: str, prefix: str, node: _GuardNode) -> _GuardNode | None:
    """Veto duplicates/aliases and keep scalar list entries out of guard ownership."""
    if _ALIAS.search(text):
        return None
    entry = _ENTRY.fullmatch(text[len(prefix) :])
    if entry is None:
        if not prefix:
            return None
        parent.content = text[len(prefix) :]
        return parent
    node.key = next(key for key in entry.groups()[:4] if key is not None)
    node.content = entry[5]
    if node.key == "<<" or any(child.key == node.key for child in parent.children):
        return None
    node.indent += len(prefix)
    parent.children.append(node)
    return node


def _guard_tokens(content: str) -> list[str] | None:
    """Decode whole YAML strings/wrappers; malformed or unsupported tokens stay unknown."""
    expression = content.strip()
    if expression.startswith('"'):
        try:
            decoded = json.loads(expression)
        except ValueError:
            return None
        if not isinstance(decoded, str):
            return None
        expression = decoded
    elif expression.startswith("'"):
        if not re.fullmatch(r"'(?:[^']|'')*'", expression):
            return None
        expression = expression[1:-1].replace("''", "'")
    expression = expression.strip()
    if expression.startswith("$" + "{{"):
        if not expression.endswith("}}"):
            return None
        expression = expression[3:-2].strip()
    tokens: list[str] = []
    while expression:
        match = _TOKEN.match(expression)
        if not match:
            return None
        if match[0].strip():
            tokens.append(match[0])
        expression = expression[len(match[0]) :]
        if len(tokens) > 128:
            return None
    return tokens


@dataclass
class _Operand:
    """Event and literal operands are distinct from conservative boolean proof."""

    kind: str = "truth"
    literal: str = ""
    truth: bool | None = None


class _GuardExpression:
    """Complete bounded parser with a token budget and three-valued evaluation."""

    def __init__(self, tokens: list[str], event: str) -> None:
        self.tokens = tokens
        self.event = event
        self.position = 0
        self.is_valid = True

    def peek(self) -> str:
        """Read the current token without advancing.

        Returns:
            The next token, or an empty sentinel at the end of the input.
        """
        return self.tokens[self.position] if self.position < len(self.tokens) else ""

    def unary(self) -> _Operand:
        """Read one operand, respecting negation before equality.

        Returns:
            The event, literal or conservative boolean operand at this position.
        """
        lexeme = self.peek()
        self.position += 1
        if lexeme == "!":
            operand = self.unary()
            result = operand.truth if operand.kind == "truth" else None
            return _Operand(truth=None if result is None else not result)
        if lexeme == "(":
            result = self.disjunction_is_true()
            if self.peek() != ")":
                self.is_valid = False
            self.position += 1
            return _Operand(truth=result)
        if lexeme.startswith("'"):
            return _Operand(kind="literal", literal=lexeme[1:-1].replace("''", "'"))
        if lexeme == "github.event_name":
            return _Operand(kind="event")
        if not _IDENTIFIER.fullmatch(lexeme):
            self.is_valid = False
        return _Operand()

    def comparison_is_true(self) -> bool | None:
        """Evaluate an exact event/literal comparison.

        Returns:
            Its boolean result, or None when the operands cannot prove one.
        """
        left = self.unary()
        operator = self.peek()
        if operator not in {"==", "!="}:
            return left.truth
        self.position += 1
        right = self.unary()
        if left.kind == "event" and right.kind == "literal":
            literal = right.literal
        elif right.kind == "event" and left.kind == "literal":
            literal = left.literal
        else:
            return None
        equal = self.event.lower() == literal.lower()
        return equal if operator == "==" else not equal

    def conjunction_is_true(self) -> bool | None:
        """Evaluate AND while still parsing both branches.

        Returns:
            False for any false branch, True for two true branches, or None otherwise.
        """
        result = self.comparison_is_true()
        while self.peek() == "&&":
            self.position += 1
            right = self.comparison_is_true()
            result = False if result is False or right is False else True if result is True and right is True else None
        return result

    def disjunction_is_true(self) -> bool | None:
        """Evaluate OR while retaining an unknown reachable branch.

        Returns:
            True for any true branch, False for two false branches, or None otherwise.
        """
        result = self.conjunction_is_true()
        while self.peek() == "||":
            self.position += 1
            right = self.conjunction_is_true()
            result = True if result is True or right is True else False if result is False and right is False else None
        return result


def _event_is_true(content: str, event: str) -> bool | None:
    """Require complete valid input before trusting even a false result."""
    tokens = _guard_tokens(content)
    if not tokens:
        return None
    parser = _GuardExpression(tokens, event)
    result = parser.disjunction_is_true()
    return result if parser.is_valid and parser.position == len(tokens) else None
