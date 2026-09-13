"""The one line-free identity a baseline stores for a finding, ratified for the family in ``contracts/core/finding-identity.v1.json``.

When a user runs ``gruff-py analyse --generate-baseline``, every ordinary finding is named by this identity and nothing positional.
On the next ``analyse --baseline-path`` a finding that moved lines still matches, while a new sibling never inherits the review.

Three decisions live here:

- a symbol-bearing finding is named by its symbol plus a declaration ordinal, so two same-named functions in one file stay apart;
- a finding naming no symbol falls back to its message with measured values normalised, so a file that grows keeps its review;
- a sensitive finding receives no identity at all, because a stored identity is what would let a review hide a secret.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar

TOOL_LANGUAGE = "py"
"""Token gruff-py contributes to every identity, so the same rule on the same path never collides with another port's finding."""

_ORDINAL_SEPARATOR = "#"
"""Joins a symbol to its declaration ordinal; a symbol containing it could forge another symbol's ordinal, so it gets no identity."""

_MEASURED_VALUE_PATTERN = re.compile(r"[0-9]+(?:[.,][0-9]+)*")
"""Every number a message can state: a length, a count, a percentage, or a version, including groups such as 1,234 or 12.5."""

_MEASURED_VALUE_PLACEHOLDER = "#"
"""What every measured value becomes in a subject, so a file that grew from 1010 to 1200 lines keeps the identity the user reviewed."""

_SENSITIVE_RULE_PREFIX = "sensitive-data."
"""Rule-id prefix that marks a secret; it is checked alongside the pillar so a mis-tagged rule still cannot be baselined."""


class BaselineIdentityError(ValueError):
    """Raised when a finding cannot be given a durable name.

    Callers surface this as a baseline diagnostic: a run that cannot name a finding must say so rather than
    silently store an ambiguous identity that would suppress the wrong occurrence later.
    """


@dataclass(frozen=True, slots=True)
class DeclarationSpan:
    """One class or function declaration and the lines it covers, used to rank same-named declarations.

    Attributes:
        start: 1-based line the declaration begins on; this is the position an ordinal ranks.
        end: 1-based last line of the declaration body, so a finding inside it resolves to the same position.
        name: Declared name as Python spells it, matched against the last segment of a finding's symbol.
    """

    start: int
    end: int
    name: str


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """One finding's durable name, plus the two facts matching needs alongside it.

    Attributes:
        identity: 16 lowercase hex characters; the only field baseline matching reads.
        subject: Readable subject the identity hashed, stored so a reviewer can see what was reviewed.
        declaration_key: Equal for two findings on one declaration; different keys under one identity are a collision.
    """

    identity: str
    subject: str
    declaration_key: str


def is_baseline_eligible(finding: Finding) -> bool:
    """Tell whether a finding may ever receive a baseline identity.

    A sensitive finding never does: it stays visible and blocking on every run until the user fixes it or
    excludes it with a written reason under ``sensitiveExclusions``.

    Args:
        finding: Any finding from the current scan.

    Returns:
        True for an ordinary finding; False for a sensitive-data finding, which a baseline counts but never stores.
    """
    return finding.pillar is not Pillar.SENSITIVE_DATA and not finding.rule_id.startswith(_SENSITIVE_RULE_PREFIX)


def normalise_measured_values(message: str) -> str:
    """Replace every measured value in a message with ``#``, per the identity amendment of 2026-09-05.

    ``"File has 1010 lines (limit 1000)"`` becomes ``"File has # lines (limit #)"``, so a file that grows keeps its review.

    Args:
        message: Finding message as the rule emitted it; it may state a length, count, percentage, or version.

    Returns:
        The message with each run of digits, including ``.`` or ``,`` groups, replaced by ``#``; unchanged when it has none.
    """
    return _MEASURED_VALUE_PATTERN.sub(_MEASURED_VALUE_PLACEHOLDER, message)


def baseline_subject(finding: Finding, ordinal: int) -> str:
    """Build the identity subject: ``symbol#ordinal`` for a symbol-bearing finding, else the normalised message.

    Args:
        finding: Finding to name; a symbol-bearing finding needs the ordinal ranked for it.
        ordinal: 1-based declaration ordinal among same-named symbols in the file; ignored for a symbol-less finding.

    Returns:
        The subject the identity hashes.

    Raises:
        BaselineIdentityError: When the symbol contains the ordinal separator, the ordinal is missing, or
            a symbol-less finding also has an empty message and so has nothing left to be named by.
    """
    symbol = finding.symbol
    # A file-level finding has nothing but its message to name it, so its measurement is stripped and a reword is a new finding.
    if not symbol:
        if not finding.message:
            raise BaselineIdentityError(f"Finding {finding.rule_id} in {finding.file_path} names neither a symbol nor a message.")
        return normalise_measured_values(finding.message)

    label = f'Finding {finding.rule_id} in {finding.file_path} has symbol "{symbol}"'
    # A symbol carrying the separator could pose as another symbol's ordinal, so it is refused rather than hashed ambiguously.
    if _ORDINAL_SEPARATOR in symbol:
        raise BaselineIdentityError(f'{label} containing "{_ORDINAL_SEPARATOR}".')
    # Defaulting a missing ordinal to 1 would merge two same-named functions back together, the collision the ordinal prevents.
    if ordinal < 1:
        raise BaselineIdentityError(f"{label} without a declaration ordinal.")
    return f"{symbol}{_ORDINAL_SEPARATOR}{ordinal}"


def compute_identity_for(tool_language: str, rule_id: str, path: str, subject: str) -> str:
    """Hash the ratified identity under an explicit tool language.

    Conformance tests use it to reproduce the digests the family oracle pins for other ports, the only proof the rule is one rule.

    Args:
        tool_language: One of go, php, py, rs, or ts.
        rule_id: Native rule id, never a concept id.
        path: Project-relative POSIX path.
        subject: Subject from :func:`baseline_subject`.

    Returns:
        16 lowercase hex characters.
    """
    joined = "\0".join([tool_language, rule_id, path, subject])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def declaration_spans(tree: ast.AST | None) -> tuple[DeclarationSpan, ...]:
    """Collect every class and function declaration in one parsed file, innermost first.

    Use from the runner: it is what lets two findings inside one function share an ordinal while a second
    declaration of the same name takes the next one.

    Args:
        tree: Parsed module AST, or ``None`` for a text file or a file that failed to parse.

    Returns:
        Declarations ordered innermost-first, so the first span containing a line is the closest declaration; empty for ``None``.
    """
    if tree is None:
        return ()
    spans: list[DeclarationSpan] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        spans.append(DeclarationSpan(start=node.lineno, end=end, name=node.name))
    return tuple(sorted(spans, key=lambda span: (span.end - span.start, span.start)))


def declaration_position_from_spans(spans_by_file: Mapping[str, tuple[DeclarationSpan, ...]]) -> Callable[[Finding], int]:
    """Build the resolver that maps a finding to the line its declaration begins on.

    The runner passes the result into baseline matching, so the ordinal counts declarations rather than lines:
    inserting code above a function moves its line and not its ordinal.

    Args:
        spans_by_file: Declarations per display path, from :func:`declaration_spans`.

    Returns:
        A resolver returning the enclosing declaration's start line, or the finding's own line when no declaration names it.
    """

    def position(finding: Finding) -> int:
        line = finding.line if finding.line is not None and finding.line > 0 else 1
        symbol = finding.symbol
        # Without a symbol there is no declaration to rank, and every symbol-less finding of one file shares a key anyway.
        if not symbol:
            return line
        wanted = symbol.rsplit(".", 1)[-1]
        for span in spans_by_file.get(finding.file_path, ()):
            if span.name == wanted and span.start <= line <= span.end:
                return span.start
        return line

    return position


def _default_declaration_position(finding: Finding) -> int:
    """Rank a symbol on its own line when the caller supplied no parsed declarations, as a direct API call does."""
    return finding.line if finding.line is not None and finding.line > 0 else 1


def finding_identities(
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None = None,
) -> tuple[FindingIdentity | None, ...]:
    """Name every eligible finding in one run, ranking same-named declarations as it goes.

    This is the single entry point baseline generation and matching both use, so a written identity and a
    matched identity can never be computed two different ways.

    Args:
        findings: This run's findings, in any order.
        declaration_position: Resolver from :func:`declaration_position_from_spans`; ``None`` ranks by the finding's own line,
            which is what a direct API caller without a parsed tree gets.

    Returns:
        One entry per input finding, aligned by index; ``None`` where the finding is sensitive and so has no identity.

    Raises:
        BaselineIdentityError: When an eligible finding cannot be named.
    """
    position = declaration_position or _default_declaration_position
    ordinals = _symbol_ordinals(findings, position)
    identities: list[FindingIdentity | None] = []
    for index, finding in enumerate(findings):
        # A sensitive finding is skipped before any hashing, so no secret ever reaches a stored identity.
        if not is_baseline_eligible(finding):
            identities.append(None)
            continue
        subject = baseline_subject(finding, ordinals[index])
        identities.append(
            FindingIdentity(
                identity=compute_identity_for(TOOL_LANGUAGE, finding.rule_id, finding.file_path, subject),
                subject=subject,
                declaration_key=_declaration_key(finding, position),
            )
        )
    return tuple(identities)


def _symbol_ordinals(findings: Sequence[Finding], position: Callable[[Finding], int]) -> tuple[int, ...]:
    """Rank each symbol-bearing finding's declaration among same-named declarations in its file.

    Two findings on one declaration share a position and therefore an ordinal; a second declaration of that
    name takes the next one, which is what stops one review from covering both.
    """
    positions_by_symbol: dict[tuple[str, str], set[int]] = {}
    for finding in findings:
        if finding.symbol and is_baseline_eligible(finding):
            positions_by_symbol.setdefault((finding.file_path, finding.symbol), set()).add(position(finding))

    ordinals: list[int] = []
    for finding in findings:
        # A symbol-less finding is named by its message, so it needs no ordinal and takes the sentinel zero.
        if not finding.symbol or not is_baseline_eligible(finding):
            ordinals.append(0)
            continue
        ranked = sorted(positions_by_symbol[(finding.file_path, finding.symbol)])
        ordinals.append(ranked.index(position(finding)) + 1)
    return tuple(ordinals)


def _declaration_key(finding: Finding, position: Callable[[Finding], int]) -> str:
    """Name the declaration a finding sits on, for collision detection only.

    A file-level finding names no declaration at all, so every symbol-less occurrence shares one key and is
    matched by count; keying them by message would report two measurements of one file as an unresolvable collision.
    """
    if not finding.symbol:
        return "declaration:file"
    return f"declaration:{position(finding)}"
