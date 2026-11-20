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
    """Return physical lines containing code or data.

    Comment and layout tokens do not count; an available AST also excludes docstrings and decorator lines.
    Tokenization failures keep nonblank lines except full-line comments, then remove any AST-known decorator lines.

    Args:
        source: Full source text of the analysed file.
        tree: AST for the same source, or None; an AST's _gruff_code_lines cache is reused or populated.

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
    """Return how many code lines a node spans, from its def, class or lambda line to its end line.

    Decorators sit above that start line and decorator lines inside the span are not code lines, so neither counts.

    Args:
        node: Function, class, async function, or lambda node to measure.
        code_lines: The file's code lines, from code_line_numbers.

    Returns:
        Number of code lines in the node's span. A node with no end line counts as one line.
    """
    end = node.end_lineno
    if end is None:
        # A node with no end line still contributes one line to the size metric.
        return 1
    return sum(1 for line in range(node.lineno, end + 1) if line in code_lines)


def logical_line_numbers(source: str, tree: ast.AST | None) -> frozenset[int]:
    """Return the first code line of each tokenizer logical line.

    Multiline expressions count once. With successful tokenization, a supplied AST excludes docstring-only and decorator-only lines.
    Tokenization failures return physical code lines without populating the logical-line cache.

    Args:
        source: Full source text of the analysed file.
        tree: AST for the same source, or None to keep docstring and decorator lines. A supplied tree can reuse or populate both line caches.

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
        if first_code_line is None and token.type not in _IGNORED_TOKEN_TYPES and token.start[0] in code_lines:
            first_code_line = token.start[0]
    lines = frozenset(starts)
    if tree is not None:
        setattr(tree, _LOGICAL_LINES_ATTRIBUTE, lines)
    return lines


def logical_lines_for_size(node: LineCountableNode, logical_lines: frozenset[int]) -> int:
    """Count logical-line starts from a node's opening line through its end line.

    Args:
        node: Definition or lambda whose span is measured.
        logical_lines: The file's logical-line starts, from logical_line_numbers.

    Returns:
        Number of logical-line starts in the span, with a minimum of one for nodes such as inline lambdas that have no start of their own.
        A node with no end line also counts as one.
    """
    end = node.end_lineno
    if end is None:
        # A node with no end line still contributes one logical line to the size metric.
        return 1
    return max(1, sum(1 for line in range(node.lineno, end + 1) if line in logical_lines))


def fallback_code_line_count(source: str) -> int:
    """Count source lines without tokenizing or parsing, leaving out blank and visibly commented lines.

    Args:
        source: Source text, possibly invalid or truncated.

    Returns:
        Number of nonblank lines whose first non-whitespace character is something other than #.
    """
    return len(_fallback_code_lines(source))


def _token_code_lines(source: str, tree: ast.AST | None) -> frozenset[int]:
    """Find physical lines containing code or data tokens, excluding comments, layout and recognised docstrings.

    Multiline tokens count on every covered line; whitespace-only error tokens do not count.
    Decorator lines remain for code_line_numbers to remove; tokenization failures use _fallback_code_lines, where docstrings count.

    Args:
        source: Full source text of the analysed file.
        tree: Parsed AST for the same source, used only to locate docstrings; None means no docstring lines are left out.

    Returns:
        One-based line numbers that hold code or data, still including decorator lines.
    """
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
    """Pick out the nonblank lines that are not full-line # comments, without tokenizing or parsing the source.

    Docstrings are not recognised here, so their lines count.

    Args:
        source: Source text, possibly invalid or truncated.

    Returns:
        One-based numbers of the lines whose stripped text is not empty and does not start with #.
    """
    return frozenset(number for number, line in enumerate(source.splitlines(), start=1) if line.strip() and not line.strip().startswith("#"))


def _decorator_lines(tree: ast.AST | None) -> frozenset[int]:
    """Collect every line covered by a decorator on a function, async function or class anywhere in the file.

    Args:
        tree: Parsed AST of the file, or None for text files and parse failures, in which case no decorator lines are found.

    Returns:
        One-based line numbers from each decorator expression's first line to its last; empty when tree is None.
    """
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
        Start/end line and character-column pairs enclosing docstring expressions; empty when tree is None or no docstrings are found.
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
    """Return the dotted symbol used by size-rule findings.

    Named ancestors precede the node name; a lambda adds a marker containing its source line.

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
    """Return ancestors in outermost-to-immediate-parent order, excluding the supplied node.

    Parent links come from the parser's _attach_parents pass; a missing parent link ends the walk.

    Args:
        node: AST node whose ancestors should be returned.

    Returns:
        Ancestors including the module when linked; an empty list when node has no parent link.
    """
    chain: list[ast.AST] = []
    current = getattr(node, "parent", None)
    while current is not None:
        chain.append(current)
        current = getattr(current, "parent", None)
    chain.reverse()
    return chain
