"""Tokenizer-backed parser for explicit ``# gruff: ...`` rule suppression comments."""

import io
import re
import tokenize
from dataclasses import dataclass, field
from typing import Literal

_DIRECTIVE_RE = re.compile(
    r"^\s*(?P<directive>[a-z-]+)\s*=\s*(?P<rule_ids>.*?)\s*$",
    re.IGNORECASE,
)
_GRUFF_COMMENT_RE = re.compile(r"\bgruff\s*:\s*(?P<body>.*)", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_REASON_SUFFIX_RE = re.compile(r"\s+(?:--?|#).*$")

SuppressionDirective = Literal["disable", "disable-next", "disable-file"]
_VALID_DIRECTIVES: frozenset[str] = frozenset({"disable", "disable-next", "disable-file"})


@dataclass(frozen=True, slots=True)
class SuppressionDiagnostic:
    """A non-finding problem found while parsing suppression comments.

    Attributes:
        type: Diagnostic category.
        message: Human-readable diagnostic text.
        line: One-based source line for the directive.
        directive: Parsed directive name, if available.
        rule_id: Parsed rule id, if available.
    """

    type: str
    message: str
    line: int
    directive: str | None = None
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedSuppressions:
    """Suppression rules parsed for one source file.

    Attributes:
        file_disabled_rule_ids: Rule ids disabled for the whole file.
        line_disabled_rule_ids: Rule ids disabled on specific source lines.
        next_line_disabled_rule_ids: Rule ids disabled by previous-line directives.
        diagnostics: Non-finding suppression parser diagnostics.
    """

    file_disabled_rule_ids: frozenset[str] = frozenset()
    line_disabled_rule_ids: dict[int, frozenset[str]] = field(default_factory=dict)
    next_line_disabled_rule_ids: dict[int, frozenset[str]] = field(default_factory=dict)
    diagnostics: tuple[SuppressionDiagnostic, ...] = ()

    def disabled_on_line(self, line: int) -> frozenset[str]:
        """Return rule ids disabled for a physical source line.

        Args:
            line: One-based physical source line.

        Returns:
            Rule ids disabled directly on the line or by ``disable-next``.
        """
        same_line = self.line_disabled_rule_ids.get(line, frozenset())
        next_line = self.next_line_disabled_rule_ids.get(line, frozenset())
        return same_line | next_line


def parse_suppressions(
    source: str,
    *,
    known_rule_ids: frozenset[str] | None = None,
) -> ParsedSuppressions:
    """Parse gruff suppression comments from *source*.

    Args:
        source: Source text to scan.
        known_rule_ids: Optional set of accepted rule ids. Unknown ids are
            reported and do not suppress anything.

    Returns:
        Parsed suppression data and parser diagnostics.
    """
    file_rule_ids: set[str] = set()
    line_rule_ids: dict[int, set[str]] = {}
    next_line_rule_ids: dict[int, set[str]] = {}
    diagnostics: list[SuppressionDiagnostic] = []

    for comment in _comment_tokens(source):
        parsed = _parse_comment(comment.text, comment.line, known_rule_ids)
        diagnostics.extend(parsed.diagnostics)
        if not parsed.rule_ids:
            continue
        if parsed.directive == "disable-file":
            file_rule_ids.update(parsed.rule_ids)
        elif parsed.directive == "disable-next":
            _add_line_rule_ids(next_line_rule_ids, comment.line + 1, parsed.rule_ids)
        elif parsed.directive == "disable":
            _add_line_rule_ids(line_rule_ids, comment.line, parsed.rule_ids)

    return ParsedSuppressions(
        file_disabled_rule_ids=frozenset(file_rule_ids),
        line_disabled_rule_ids=_freeze_line_map(line_rule_ids),
        next_line_disabled_rule_ids=_freeze_line_map(next_line_rule_ids),
        diagnostics=tuple(diagnostics),
    )


@dataclass(frozen=True, slots=True)
class _CommentToken:
    """Source comment token with its physical line number."""

    text: str
    line: int


@dataclass(frozen=True, slots=True)
class _ParsedComment:
    """Parsed suppression directive plus diagnostics for one comment."""

    directive: SuppressionDirective | None
    rule_ids: frozenset[str]
    diagnostics: tuple[SuppressionDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class _DirectiveParts:
    """Validated suppression directive name plus its raw rule-id tokens."""

    directive: SuppressionDirective
    raw_rule_ids: tuple[str, ...]


def _comment_tokens(source: str) -> list[_CommentToken]:
    tokens: list[_CommentToken] = []
    try:
        stream = io.StringIO(source).readline
        for token in tokenize.generate_tokens(stream):
            if token.type == tokenize.COMMENT:
                tokens.append(_CommentToken(text=token.string, line=token.start[0]))
    except (tokenize.TokenError, SyntaxError):
        # The tokenizer raises IndentationError (a SyntaxError) on bad
        # dedents; suppressions run on unparseable files, so keep what was
        # collected instead of crashing the run.
        return tokens
    return tokens


def _parse_comment(
    comment_text: str,
    line: int,
    known_rule_ids: frozenset[str] | None,
) -> _ParsedComment:
    marker = _GRUFF_COMMENT_RE.search(comment_text)
    if marker is None:
        return _ParsedComment(directive=None, rule_ids=frozenset())

    parts, diagnostics = _parse_directive_parts(marker.group("body"), line)
    if parts is None:
        return _ParsedComment(directive=None, rule_ids=frozenset(), diagnostics=diagnostics)

    accepted, diagnostics = _accepted_rule_ids(
        parts.raw_rule_ids,
        directive=parts.directive,
        line=line,
        known_rule_ids=known_rule_ids,
    )
    return _ParsedComment(
        directive=parts.directive,
        rule_ids=frozenset(accepted),
        diagnostics=diagnostics,
    )


def _parse_directive_parts(
    body: str,
    line: int,
) -> tuple[_DirectiveParts | None, tuple[SuppressionDiagnostic, ...]]:
    match = _DIRECTIVE_RE.match(_REASON_SUFFIX_RE.sub("", body))
    if match is None:
        return None, _invalid_comment(line, "Malformed gruff suppression comment.").diagnostics

    directive = match.group("directive").lower()
    if directive not in _VALID_DIRECTIVES:
        return None, _invalid_comment(
            line,
            f'Unknown gruff suppression directive "{directive}".',
        ).diagnostics

    raw_rule_ids = _split_rule_ids(match.group("rule_ids"))
    if not raw_rule_ids:
        return None, _invalid_comment(
            line,
            "Suppression must name at least one explicit rule id.",
        ).diagnostics

    return _DirectiveParts(_as_directive(directive), raw_rule_ids), ()


def _split_rule_ids(rule_ids_text: str) -> tuple[str, ...]:
    raw_rule_ids = tuple(item.strip() for item in rule_ids_text.split(","))
    if not raw_rule_ids or any(not item for item in raw_rule_ids):
        return ()
    return raw_rule_ids


def _accepted_rule_ids(
    raw_rule_ids: tuple[str, ...],
    *,
    directive: SuppressionDirective,
    line: int,
    known_rule_ids: frozenset[str] | None,
) -> tuple[set[str], tuple[SuppressionDiagnostic, ...]]:
    accepted: set[str] = set()
    diagnostics: list[SuppressionDiagnostic] = []
    for rule_id in raw_rule_ids:
        diagnostic = _rule_id_diagnostic(rule_id, directive, line, known_rule_ids)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            continue
        accepted.add(rule_id)
    return accepted, tuple(diagnostics)


def _rule_id_diagnostic(
    rule_id: str,
    directive: SuppressionDirective,
    line: int,
    known_rule_ids: frozenset[str] | None,
) -> SuppressionDiagnostic | None:
    if not _RULE_ID_RE.match(rule_id):
        return SuppressionDiagnostic(
            type="suppression-parse-error",
            message=f'Invalid gruff rule id "{rule_id}".',
            line=line,
            directive=directive,
            rule_id=rule_id,
        )
    if known_rule_ids is not None and rule_id not in known_rule_ids:
        return SuppressionDiagnostic(
            type="suppression-unknown-rule",
            message=f'Unknown gruff rule id "{rule_id}".',
            line=line,
            directive=directive,
            rule_id=rule_id,
        )
    return None


def _invalid_comment(line: int, message: str) -> _ParsedComment:
    return _ParsedComment(
        directive=None,
        rule_ids=frozenset(),
        diagnostics=(
            SuppressionDiagnostic(
                type="suppression-parse-error",
                message=message,
                line=line,
            ),
        ),
    )


def _as_directive(value: str) -> SuppressionDirective:
    if value not in _VALID_DIRECTIVES:
        raise ValueError(f"Unsupported suppression directive: {value}")
    return value  # type: ignore[return-value]  # directive literal validated


def _add_line_rule_ids(target: dict[int, set[str]], line: int, rule_ids: frozenset[str]) -> None:
    target.setdefault(line, set()).update(rule_ids)


def _freeze_line_map(value: dict[int, set[str]]) -> dict[int, frozenset[str]]:
    return {line: frozenset(rule_ids) for line, rule_ids in sorted(value.items())}
