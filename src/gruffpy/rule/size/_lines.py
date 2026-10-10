"""Shared line-counting helpers for every rule that compares a unit's length with a threshold.

Defined by ADR-002, as amended for FAMILY-CONTRACT section 12's code-lines clause (search: ``Code lines in every line
count``): a unit's length is the number of code lines it spans. Blank lines, ``#`` comments, PEP 257 docstrings and
decorator lines never count, so documenting a unit cannot push it over a limit. File, class,
average-function and test-function length, setup length, the test-to-subject ratio and the maintainability index's
line term all read the same per-file set of code lines.

Function length is the one exception (FAMILY-CONTRACT section 12, search: ``Measures that stop counting data or syntax
as logic``): it counts logical lines, so a literal or a call that spans several lines counts once. Docstrings and
decorators stay free there too.
"""

import ast
import io
import tokenize

LineCountableNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda

# The per-file code-line and logical-line sets are stored on the parsed tree, so the rules that measure one file compute each set once.
_CODE_LINES_ATTRIBUTE = "_gruff_code_lines"
_LOGICAL_LINES_ATTRIBUTE = "_gruff_logical_lines"
_IGNORED_TOKEN_TYPES = frozenset(
    {
        tokenize.COMMENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.NEWLINE,
        tokenize.NL,
    }
)


def code_line_numbers(source: str, tree: ast.AST | None) -> frozenset[int]:
    """Return the physical line numbers of a file that carry code.

    A line is left out when it is blank, holds only a ``#`` comment, belongs to a PEP 257 docstring (the first
    statement of a module, class or function body), or belongs to a decorator. String literals used as data keep
    counting. Docstring and decorator lines are found from *tree*, so they count when *tree* is None; source that
    cannot be tokenized falls back to leaving out blank and visibly commented lines.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST for the same source, or None for text files and parse failures.

    Returns:
        One-based line numbers that hold code or data.
    """
    if tree is not None:
        cached = getattr(tree, _CODE_LINES_ATTRIBUTE, None)
        if isinstance(cached, frozenset):
            return cached
    lines = _token_code_lines(source, tree) - _decorator_lines(tree)
    if tree is not None:
        setattr(tree, _CODE_LINES_ATTRIBUTE, lines)
    return lines


def lines_for_size(node: LineCountableNode, code_lines: frozenset[int]) -> int:
    """Return how many code lines a node spans, from its ``def``, ``class`` or ``lambda`` line to its end line.

    Decorators sit above that start line and decorator lines inside the span are not code lines, so neither counts.

    Args:
        node: Function, class, async function, or lambda node to measure.
        code_lines: The file's code lines, from ``code_line_numbers``.

    Returns:
        Number of code lines in the node's span; at least 1 for a node whose end line is unknown.
    """
    end = node.end_lineno
    if end is None:
        # Defensive: Python >= 3.8 always populates end_lineno on nodes returned by ast.parse().
        return 1
    return sum(1 for line in range(node.lineno, end + 1) if line in code_lines)


def logical_line_numbers(source: str, tree: ast.AST | None) -> frozenset[int]:
    """Return the start line of every logical line of code in a file.

    A logical line is what the tokenizer ends with a NEWLINE token: one statement, or one compound-statement header,
    however many physical lines its literals, calls or brackets span. A logical line made only of a docstring or a
    decorator is left out, as ``code_line_numbers`` leaves those lines out. Source that cannot be tokenized falls back
    to the code lines themselves.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST for the same source, or None for text files and parse failures.

    Returns:
        One-based line numbers where a logical line of code starts.
    """
    if tree is not None:
        cached = getattr(tree, _LOGICAL_LINES_ATTRIBUTE, None)
        if isinstance(cached, frozenset):
            return cached
    code_lines = code_line_numbers(source, tree)
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return code_lines
    starts: set[int] = set()
    first_code_line: int | None = None
    for token in tokens:
        if token.type == tokenize.NEWLINE:
            if first_code_line is not None:
                starts.add(first_code_line)
            first_code_line = None
            continue
        # The logical line starts at its first token that sits on a code line.
        if first_code_line is None and token.type not in _IGNORED_TOKEN_TYPES and token.start[0] in code_lines:
            first_code_line = token.start[0]
    lines = frozenset(starts)
    if tree is not None:
        setattr(tree, _LOGICAL_LINES_ATTRIBUTE, lines)
    return lines


def logical_lines_for_size(node: LineCountableNode, logical_lines: frozenset[int]) -> int:
    """Return how many logical lines start in a node's span, from its ``def`` or ``lambda`` line to its end line.

    Args:
        node: Function, async function, or lambda node to measure.
        logical_lines: The file's logical-line starts, from ``logical_line_numbers``.

    Returns:
        Number of logical lines that start in the node's span; at least 1, since a lambda inside a longer statement
        starts no logical line of its own.
    """
    end = node.end_lineno
    if end is None:
        # Defensive: Python >= 3.8 always populates end_lineno on nodes returned by ast.parse().
        return 1
    return max(1, sum(1 for line in range(node.lineno, end + 1) if line in logical_lines))


def fallback_code_line_count(source: str) -> int:
    """Count source lines without tokenizing or parsing, leaving out blank and visibly commented lines.

    Args:
        source: Source text, possibly invalid or truncated.

    Returns:
        Nonblank lines that are not full-line ``#`` comments.
    """
    return len(_fallback_code_lines(source))


def _token_code_lines(source: str, tree: ast.AST | None) -> frozenset[int]:
    docstring_spans = _docstring_source_spans(tree, source.splitlines())
    try:
        tokens = tuple(tokenize.generate_tokens(io.StringIO(source).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return _fallback_code_lines(source)
    lines: set[int] = set()
    for token in tokens:
        if token.type in _IGNORED_TOKEN_TYPES:
            continue
        if token.type == tokenize.ERRORTOKEN and token.string.isspace():
            continue
        if _is_inside_docstring_span(token, docstring_spans):
            continue
        lines.update(range(token.start[0], token.end[0] + 1))
    return frozenset(lines)


def _fallback_code_lines(source: str) -> frozenset[int]:
    return frozenset(number for number, line in enumerate(source.splitlines(), start=1) if line.strip() and not line.strip().startswith("#"))


def _decorator_lines(tree: ast.AST | None) -> frozenset[int]:
    if tree is None:
        return frozenset()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            for decorator in node.decorator_list:
                lines.update(range(decorator.lineno, (decorator.end_lineno or decorator.lineno) + 1))
    return frozenset(lines)


def _docstring_source_spans(
    tree: ast.AST | None,
    source_lines: list[str],
) -> tuple[tuple[tuple[int, int], tuple[int, int]], ...]:
    """Collect token-compatible source spans for PEP 257 docstrings.

    Args:
        tree: Parsed AST, or None when the source did not parse.
        source_lines: Source without newline terminators, used to normalize byte columns.

    Returns:
        Start/end positions that enclose only conventional docstring tokens.
    """
    if tree is None:
        return ()
    spans: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        is_docstring = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
        if not is_docstring:
            continue
        end_line = first.end_lineno or first.lineno
        end_column = first.end_col_offset or first.col_offset
        spans.append(
            (
                (first.lineno, _character_column(source_lines, first.lineno, first.col_offset)),
                (end_line, _character_column(source_lines, end_line, end_column)),
            )
        )
    return tuple(spans)


def _character_column(source_lines: list[str], line_number: int, byte_column: int) -> int:
    """Convert an AST UTF-8 byte column to tokenize's character column.

    Args:
        source_lines: Source without newline terminators.
        line_number: One-based source line containing the offset.
        byte_column: Zero-based UTF-8 byte offset reported by the AST.

    Returns:
        Zero-based Unicode character offset on the same line.
    """
    line = source_lines[line_number - 1]
    return len(line.encode("utf-8")[:byte_column].decode("utf-8"))


def _is_inside_docstring_span(
    token: tokenize.TokenInfo,
    spans: tuple[tuple[tuple[int, int], tuple[int, int]], ...],
) -> bool:
    """Return whether a token belongs to a conventional docstring expression.

    Args:
        token: Token whose physical lines would otherwise count as source.
        spans: Parsed docstring boundaries in tokenize-compatible coordinates.

    Returns:
        True only when the complete token lies inside one docstring expression.
    """
    return any(start <= token.start and token.end <= end for start, end in spans)


def qualified_symbol(node: ast.AST, parents: list[ast.AST]) -> str:
    """Return a qualified dotted name using a node's parent chain.

    Used by size rules so findings carry a stable `symbol` field
    (e.g. ``ClassA.method_b`` or ``module_func``). The parents list is the
    parent AST chain from outermost (Module) to innermost (immediate parent).

    Args:
        node: AST node whose symbol should be rendered.
        parents: Parent AST chain from outermost to immediate parent.

    Returns:
        Dotted symbol name, lambda marker, or ``<module>`` fallback.
    """
    parts: list[str] = []
    for ancestor in parents:
        name = getattr(ancestor, "name", None)
        if isinstance(name, str):
            parts.append(name)
    own = getattr(node, "name", None)
    if isinstance(own, str):
        parts.append(own)
    elif isinstance(node, ast.Lambda):
        parts.append(f"<lambda:{node.lineno}>")
    return ".".join(parts) if parts else "<module>"


def parent_chain(node: ast.AST) -> list[ast.AST]:
    """Walk parent links upward and return the ancestor chain.

    Walks `parent` links from a node and returns ancestors
    from outermost (closest to module) to immediate parent (excluding *node*).

    Requires the parser to have attached `parent` attributes (the gruff-py
    parser does this in `_attach_parents`).

    Args:
        node: AST node whose ancestors should be returned.

    Returns:
        Ancestor chain from module-adjacent parent to immediate parent.
    """
    chain: list[ast.AST] = []
    current = getattr(node, "parent", None)
    while current is not None:
        chain.append(current)
        current = getattr(current, "parent", None)
    chain.reverse()
    return chain
