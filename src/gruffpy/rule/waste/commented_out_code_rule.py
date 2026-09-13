"""Source comment tokens that parse as Python code.

Two-stage heuristic:

1. A cheap regex pre-filter rejects most comment styles ("TODO:", english
   prose, license headers, etc.) without invoking the parser.
2. Remaining candidates go through ``ast.parse`` - if the parser accepts
   them, the comment is flagged.

Tokenization supplies the source comments, so docstrings and ordinary string
literals that contain ``#`` examples are not scanned as comments.

Full-line comments on consecutive lines are judged as one block: a task-marker
header covers every line beneath it, the line after a colon-ended prose line is
what that line introduces, an expression that finishes a sentence still running
on (``... works in conjunction with`` then ``distinct()``) is prose, and lines
indented under an example-cue header such as ``Some examples:`` are quoted
examples. A line that leaves a bracket open, such as ``eq_(``, is code rather
than prose. A tombstoned function with no such header still reports one
finding per code line, and so does a call with arguments under a finished
remark.

Confidence: LOW. False positives are easy on prose comments that happen to
look like valid Python (``# x is the same as y``). Use the per-rule
suppression knob (TBD) when needed.
"""

import ast
import io
import keyword
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

# Pre-filter: must look like a statement-or-assignment-or-call before we
# bother running the compiler.
_CODE_LIKE = re.compile(
    r"""^\s*\#\s*
    (
        # `x = expr` / `x += expr` / etc.
        [A-Za-z_][\w.]*\s*[+\-*/%&|^]?=\s*\S
        |
        # `name(...)` call
        [A-Za-z_][\w.]*\(\S
        |
        # `if cond:` / `for x in y:` / `while cond:` / `return expr`
        (?:return|raise|yield|assert|if|elif|while|for|with|try|except|finally|break|continue|pass)\b
        |
        # `print x` or `import x` style
        (?:import|from)\b
    )
    """,
    re.VERBOSE,
)

# Comments to skip even if they look code-like
_SKIP_PATTERNS = (
    re.compile(r"^\s*#\s*(TODO|FIXME|XXX|HACK|NOTE|TBD)\b", re.IGNORECASE),
    re.compile(r"^\s*#\s*type\s*:", re.IGNORECASE),
    re.compile(r"^\s*#\s*pragma\s*:", re.IGNORECASE),
    re.compile(r"^\s*#\s*noqa\b", re.IGNORECASE),
    re.compile(r"^\s*#\s*pylint\b", re.IGNORECASE),
    re.compile(r"^\s*#!/", re.IGNORECASE),
    re.compile(r"^\s*#\s*coding[:=]", re.IGNORECASE),
)
# A task marker opening a comment block annotates the whole block, not only its first line.
_TASK_MARKER_PATTERN = _SKIP_PATTERNS[0]
# A prose line ending in one of these closes its sentence; a colon instead introduces what follows.
_SENTENCE_TERMINATORS = (".", "!", "?")
# Prose needs a word; a separator such as ``# -----`` introduces nothing.
_PROSE_WORD = re.compile(r"[A-Za-z]{2,}")
# A colon-ended prose header with one of these cues introduces example snippets indented beneath it.
_EXAMPLE_CUE = re.compile(r"(?:\be\.g\.|\bexamples?\b|\bfor instance\b|\bsuch as\b|\busage\b|\blike (?:so|this)\b)", re.IGNORECASE)
# A sentence cannot stop on one of these words, so a line ending with one runs on into the line below it.
_CONTINUING_WORDS: frozenset[str] = frozenset(
    {
        *("a", "an", "the"),
        *("as", "at", "by", "for", "from", "in", "into", "like", "of", "on", "onto", "per", "than", "to", "under", "via", "with"),
        *("and", "or", "but", "nor", "because", "if", "unless", "until", "whether", "while"),
        *("is", "are", "was", "were", "be", "been"),
        *("call", "calls", "called", "calling", "invoke", "invokes", "invoked", "using"),
    }
)
_WORD = re.compile(r"[A-Za-z']+")


@dataclass(frozen=True, slots=True)
class _CommentLine:
    """One source comment token, positioned as the physical line it came from.

    Attributes:
        lineno: One-based source line of the comment.
        line: The comment text preceded by its column's worth of spaces.
        is_full_line: Whether no code precedes the comment on its line.
    """

    lineno: int
    line: str
    is_full_line: bool


class CommentedOutCodeRule(Rule):
    """Detect source comments that pass `ast.parse` after the code-like pre-filter accepts them."""

    ID = "waste.commented-out-code"

    def definition(self) -> RuleDefinition:
        """Describe the commented-out-code rule as a low-confidence advisory.

        Low confidence reflects the parser-based heuristic - prose comments
        that happen to look like Python (``# x is the same as y``) can trip it.

        Returns:
            Definition for the commented-out-code rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Commented-out code",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan source comment tokens for comments that parse as Python statements.

        Lines matching ``TODO``/``FIXME``/``type:``/``pragma:``/``noqa``/etc.
        are skipped before the parser runs, so the regex pre-filter only
        forwards statement-shaped candidates. Python's tokenizer excludes
        docstring and string-literal contents from this comment stream, and
        each comment block is judged before its lines are.

        Args:
            unit: Parsed source file (only ``unit.source`` is used here).
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per line whose comment body re-parses as Python code.
        """
        if not unit.source:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for block in _comment_blocks(unit.source):
            for comment in _block_candidates(block):
                line = comment.line
                if any(p.search(line) for p in _SKIP_PATTERNS):
                    continue
                if not _CODE_LIKE.search(line):
                    continue
                candidate = _strip_comment_prefix(line)
                if not _is_valid_python(candidate):
                    continue
                findings.append(self._finding(definition, unit, comment.lineno, candidate))
        return findings

    @staticmethod
    def _finding(definition: RuleDefinition, unit: AnalysisUnit, lineno: int, candidate: str) -> Finding:
        """Build the finding for one commented-out code line.

        Args:
            definition: This rule's metadata.
            unit: Source file the comment belongs to.
            lineno: One-based line of the comment.
            candidate: Comment body with its ``#`` prefix removed.

        Returns:
            The advisory shown to the user, previewing the commented-out code.
        """
        return Finding(
            rule_id=definition.id,
            message=f"Commented-out code on line {lineno}.",
            file_path=unit.file.display_path,
            line=lineno,
            severity=definition.default_severity,
            pillar=definition.pillar,
            tier=definition.tier,
            confidence=definition.confidence,
            end_line=lineno,
            remediation="Delete the comment or convert it to prose if it's documentation.",
            secondary_pillars=definition.secondary_pillars,
            metadata={"preview": candidate.strip()[:80]},
        )


def _comment_blocks(source: str) -> list[list[_CommentLine]]:
    """Group full-line comments on consecutive lines into blocks; an inline comment stands alone.

    Args:
        source: Raw source text whose comment tokens are grouped.

    Returns:
        Blocks in source order, each holding at least one comment line.
    """
    blocks: list[list[_CommentLine]] = []
    # Each comment either extends the block directly above it or starts a new one.
    for comment in _comment_token_lines(source):
        previous = blocks[-1][-1] if blocks else None
        # A full-line comment directly below another full-line comment belongs to the same block.
        if comment.is_full_line and previous is not None and previous.is_full_line and previous.lineno == comment.lineno - 1:
            blocks[-1].append(comment)
            continue
        blocks.append([comment])
    return blocks


def _block_candidates(block: list[_CommentLine]) -> Iterator[_CommentLine]:
    """Yield the lines of one comment block that can still be commented-out code.

    Args:
        block: Consecutive comment lines judged together.

    Returns:
        Iterator over lines outside a task-marker block, a prose sentence's tail, and an example snippet.
    """
    # A task marker on the block's first line describes pending work for every line beneath it.
    if _TASK_MARKER_PATTERN.search(block[0].line):
        return
    example_indent: int | None = None
    previous_text = ""
    # Each line is judged against the header and the line directly above it.
    for comment in block:
        body = _comment_body(comment.line)
        text = body.strip()
        indent = len(body) - len(body.lstrip(" "))
        # A non-empty line back at the example header's indentation ends its snippet region.
        if example_indent is not None and text and indent <= example_indent:
            example_indent = None
        # Neither a quoted example nor the tail of a prose sentence is code the author commented out.
        if not (example_indent is not None and text) and not _is_prose_continuation(previous_text, text):
            yield comment
        # A colon-ended prose header with an example cue opens a region for the indented lines below it.
        if text.endswith(":") and _EXAMPLE_CUE.search(text) and _is_prose(text):
            example_indent = indent
        previous_text = text


def _is_prose_continuation(previous_text: str, text: str) -> bool:
    """Return whether a comment line belongs to the prose on the line above rather than being code.

    Args:
        previous_text: Stripped comment body of the line above; empty means a blank comment line.
        text: Stripped comment body of the line being judged.

    Returns:
        True when the line above is prose ending in a colon, which introduces whatever follows, or a sentence
        still running onto an expression: the line above stops on a word such as ``with`` or ``called``, or the
        expression only names functions, as ``annotate()`` does. A call with arguments under a finished remark
        such as ``no temp materialized view at the moment`` is code the author disabled, so it still reports.
    """
    # Only prose can carry a sentence or introduce a snippet onto the next line.
    if not _is_prose(previous_text):
        return False
    # A colon hands the reader whatever follows: an example value, a replacement, or a quoted snippet.
    if previous_text.endswith(":"):
        return True
    if previous_text.endswith(_SENTENCE_TERMINATORS):
        return False
    expression = _bare_expression(text)
    if expression is None:
        return False
    words = _WORD.findall(previous_text)
    is_sentence_running_on = previous_text.endswith(",") or (bool(words) and words[-1].lower() in _CONTINUING_WORDS)
    return is_sentence_running_on or _is_function_reference(expression)


def _is_prose(text: str) -> bool:
    """Return whether a stripped comment body is words rather than code or a separator.

    Args:
        text: Stripped comment body.

    Returns:
        True when the body holds a word, does not open with a Python keyword such as ``else:``, is not
        statement-shaped, leaves no bracket unclosed the way ``eq_(`` or ``) -> List[str]:`` do, and does not
        parse as Python.
    """
    first_word = text.split(maxsplit=1)[0].rstrip(":") if text else ""
    opened = sum(text.count(bracket) for bracket in "([{")
    closed = sum(text.count(bracket) for bracket in ")]}")
    return (
        bool(_PROSE_WORD.search(text))
        and not keyword.iskeyword(first_word)
        and opened == closed
        and not _CODE_LIKE.search(f"# {text}")
        and not _is_valid_python(text)
    )


def _bare_expression(text: str) -> ast.expr | None:
    """Return the expression a stripped comment body consists of, the way a wrapped sentence ends.

    Args:
        text: Stripped comment body.

    Returns:
        The single expression, such as the call in ``extra()``; ``None`` for statements and unparseable text.
    """
    try:
        module = ast.parse(f"{text}\n")
    except (SyntaxError, ValueError):
        return None
    if len(module.body) == 1 and isinstance(module.body[0], ast.Expr):
        return module.body[0].value
    return None


def _is_function_reference(expression: ast.expr) -> bool:
    """Return whether an expression names functions rather than calling one with data.

    Args:
        expression: Expression parsed from a comment line.

    Returns:
        True when it holds a call and every call in it has no arguments, as in ``connect() or connection.begin()``.
    """
    calls = [node for node in ast.walk(expression) if isinstance(node, ast.Call)]
    return bool(calls) and all(not call.args and not call.keywords for call in calls)


def _comment_body(line: str) -> str:
    """Return the text after a comment's ``#``, keeping the spaces that indent it.

    Args:
        line: Comment line as returned by ``_comment_token_lines``.

    Returns:
        Everything after the first ``#``; empty for a bare ``#``.
    """
    return line[line.find("#") + 1 :]


def _comment_token_lines(source: str) -> list[_CommentLine]:
    """Return physical-line-shaped comment lines for tokenizer COMMENT tokens.

    Comments collected before a tokenizer failure are kept: the tokenizer
    raises ``TokenError`` on EOF-in-statement shapes and ``IndentationError``
    (a ``SyntaxError``) on bad dedents, and this rule runs on unparseable
    files, so a broken file degrades to a partial comment scan instead of
    crashing the analysis run.
    """
    comments: list[_CommentLine] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            row, col = token.start
            comments.append(_CommentLine(lineno=row, line=f"{' ' * col}{token.string}", is_full_line=not token.line[:col].strip()))
    except (tokenize.TokenError, SyntaxError):
        pass
    return comments


def _strip_comment_prefix(line: str) -> str:
    """Return *line* with the leading ``#`` and at most one space stripped,
    preserving original indentation so ``compile`` sees consistent levels."""
    index = line.find("#")
    if index < 0:
        return line
    indent = line[:index]
    body = line[index + 1 :]
    if body.startswith(" "):
        body = body[1:]
    return indent + body


def _is_valid_python(candidate: str) -> bool:
    """Return True if *candidate* parses as Python (top-level or function-body)."""
    dedented = candidate.lstrip()
    if not dedented:
        return False
    # Try top-level first; if it fails, wrap in a function so `return`,
    # `yield`, `continue`, `break` parse too.
    probes = [dedented, f"def __probe__():\n    {dedented}"]
    if dedented.rstrip().endswith(":"):
        probes.extend(
            [
                f"{dedented}\n    pass",
                f"def __probe__():\n    {dedented}\n        pass",
            ]
        )
    for wrap in probes:
        try:
            ast.parse(wrap + "\n")
        except (SyntaxError, ValueError):
            continue
        return True
    return False
