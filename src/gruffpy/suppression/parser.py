"""Parser for explicit ``# gruff: ...`` rule suppressions."""

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

SuppressionDirective = Literal["disable", "disable-next", "disable-file"]
_VALID_DIRECTIVES: frozenset[str] = frozenset({"disable", "disable-next", "disable-file"})


@dataclass(frozen=True, slots=True)
class SuppressionDiagnostic:
    """A non-finding problem found while parsing suppression comments."""

    type: str
    message: str
    line: int
    directive: str | None = None
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedSuppressions:
    """Suppression rules parsed for one source file."""

    file_disabled_rule_ids: frozenset[str] = frozenset()
    line_disabled_rule_ids: dict[int, frozenset[str]] = field(default_factory=dict)
    next_line_disabled_rule_ids: dict[int, frozenset[str]] = field(default_factory=dict)
    diagnostics: tuple[SuppressionDiagnostic, ...] = ()

    def disabled_on_line(self, line: int) -> frozenset[str]:
        """Return rule ids disabled for a physical source line."""
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
    text: str
    line: int


@dataclass(frozen=True, slots=True)
class _ParsedComment:
    directive: SuppressionDirective | None
    rule_ids: frozenset[str]
    diagnostics: tuple[SuppressionDiagnostic, ...] = ()


def _comment_tokens(source: str) -> list[_CommentToken]:
    tokens: list[_CommentToken] = []
    try:
        stream = io.StringIO(source).readline
        for token in tokenize.generate_tokens(stream):
            if token.type == tokenize.COMMENT:
                tokens.append(_CommentToken(text=token.string, line=token.start[0]))
    except tokenize.TokenError:
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

    body = marker.group("body")
    match = _DIRECTIVE_RE.match(body)
    if match is None:
        return _invalid_comment(line, "Malformed gruff suppression comment.")

    directive = match.group("directive").lower()
    if directive not in _VALID_DIRECTIVES:
        return _invalid_comment(line, f'Unknown gruff suppression directive "{directive}".')

    rule_ids_text = match.group("rule_ids")
    raw_rule_ids = [item.strip() for item in rule_ids_text.split(",")]
    if not raw_rule_ids or any(not item for item in raw_rule_ids):
        return _invalid_comment(line, "Suppression must name at least one explicit rule id.")

    accepted: set[str] = set()
    diagnostics: list[SuppressionDiagnostic] = []
    for rule_id in raw_rule_ids:
        if not _RULE_ID_RE.match(rule_id):
            diagnostics.append(
                SuppressionDiagnostic(
                    type="suppression-parse-error",
                    message=f'Invalid gruff rule id "{rule_id}".',
                    line=line,
                    directive=directive,
                    rule_id=rule_id,
                )
            )
            continue
        if known_rule_ids is not None and rule_id not in known_rule_ids:
            diagnostics.append(
                SuppressionDiagnostic(
                    type="suppression-unknown-rule",
                    message=f'Unknown gruff rule id "{rule_id}".',
                    line=line,
                    directive=directive,
                    rule_id=rule_id,
                )
            )
            continue
        accepted.add(rule_id)

    return _ParsedComment(
        directive=_as_directive(directive),
        rule_ids=frozenset(accepted),
        diagnostics=tuple(diagnostics),
    )


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
    return value  # type: ignore[return-value]


def _add_line_rule_ids(target: dict[int, set[str]], line: int, rule_ids: frozenset[str]) -> None:
    target.setdefault(line, set()).update(rule_ids)


def _freeze_line_map(value: dict[int, set[str]]) -> dict[int, frozenset[str]]:
    return {line: frozenset(rule_ids) for line, rule_ids in sorted(value.items())}
