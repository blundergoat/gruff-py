"""The one line-free identity a baseline stores for a finding, ratified for the family in ``contracts/core/finding-identity.v1.json``.

When a user runs ``gruff-py analyse --generate-baseline``, every ordinary finding is named by this identity and nothing positional.
On the next ``analyse --baseline PATH``, a finding that moved lines still matches when its declaration keeps its ordinal.

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

_LAMBDA_POSITION = re.compile(r"<lambda:[0-9]+>")

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
    """Record which source lines belong to a class, function or lambda.

    Baseline matching uses the spans to associate decorator and body findings with the same declaration.
    The name, including enclosing scopes when known, keeps unrelated declarations apart.

    Attributes:
        start: 1-based line the declaration begins on; this is the position an ordinal ranks.
        end: 1-based last line of the declaration body, so a finding inside it resolves to the same position.
        name: Short declaration name, with a shared marker for lambdas.
        qualified_name: Dotted declaration name when its enclosing scopes are known.
    """

    start: int
    end: int
    name: str
    qualified_name: str = ""


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """Carry the durable name used to recognise a reviewed finding in a later scan.

    The report can show the subject so a reviewer can recognise the original finding.
    The matcher uses the declaration key to detect identities shared by unrelated declarations.

    Attributes:
        identity: 16 lowercase hex characters; the only field baseline matching reads.
        subject: Readable subject the identity hashed, stored so a reviewer can see what was reviewed.
        declaration_key: Equal for two findings on one declaration; different keys under one identity are a collision.
    """

    identity: str
    subject: str
    declaration_key: str


def is_baseline_eligible(finding: Finding) -> bool:
    """Check whether a finding passes the sensitive-data requirement for a baseline identity.

    A baseline cannot suppress a sensitive finding; separate exclusion and failure-threshold policies still apply.

    Args:
        finding: Any finding from the current scan.

    Returns:
        True if the pillar is non-sensitive and the rule ID lacks the "sensitive-data." prefix.
        Baselines count sensitive findings without storing them.
    """
    return finding.pillar is not Pillar.SENSITIVE_DATA and not finding.rule_id.startswith(_SENSITIVE_RULE_PREFIX)


def has_baseline_identity(finding: Finding) -> bool:
    """Check whether a finding is allowed to proceed to baseline subject construction.

    A sensitive finding never is, and neither is one whose symbol carries the ordinal separator, which could pose as
    another symbol's ordinal. Such a finding cannot be stored in or matched against a baseline.

    Args:
        finding: Any finding from the current scan.

    Returns:
        True when the finding is eligible and its symbol, if any, is free of the ordinal separator.
    """
    return is_baseline_eligible(finding) and _ORDINAL_SEPARATOR not in (finding.symbol or "")


def normalise_measured_values(message: str) -> str:
    """Mask numbers in a finding message so a measurement can change without changing its baseline subject.

    A message such as File has 1010 lines (limit 1000) becomes File has # lines (limit #).

    Args:
        message: Finding message as the rule emitted it; it may state a length, count, percentage, or version.

    Returns:
        The message with each ASCII digit sequence, including groups joined by a dot or comma, replaced by #. Text with no match stays unchanged.
    """
    return _MEASURED_VALUE_PATTERN.sub(_MEASURED_VALUE_PLACEHOLDER, message)


def baseline_subject(finding: Finding, ordinal: int) -> str:
    """Build the label a baseline uses to recognise a finding on future scans.
    Use a declaration ordinal for a symbol or a normalized message for a finding that has no symbol.

    Args:
        finding: Finding to name; a symbol-bearing finding needs the ordinal ranked for it.
        ordinal: 1-based declaration ordinal among same-named symbols in the file; ignored for a symbol-less finding.

    Returns:
        The subject the identity hashes.

    Raises:
        BaselineIdentityError: When the symbol contains the ordinal separator, the ordinal for a symbol-bearing finding is below 1, or
            a symbol-less finding also has an empty message and so has nothing left to be named by.
    """
    symbol = finding.symbol
    # A symbol-less finding uses its message as the subject. Changes limited to the measured numbers can keep the same subject.
    if not symbol:
        # A finding without either label cannot be matched safely against reviewed debt.
        if not finding.message:
            raise BaselineIdentityError(f"Finding {finding.rule_id} in {finding.file_path} names neither a symbol nor a message.")
        return normalise_measured_values(finding.message)

    label = f'Finding {finding.rule_id} in {finding.file_path} has symbol "{symbol}"'
    # Reserve the separator so a symbol-bearing subject has one boundary between the symbol and its ordinal.
    if _ORDINAL_SEPARATOR in symbol:
        raise BaselineIdentityError(f'{label} containing "{_ORDINAL_SEPARATOR}".')
    # Defaulting an invalid ordinal to 1 could give this finding the identity of another declaration with the same symbol.
    if ordinal < 1:
        raise BaselineIdentityError(f"{label} without a declaration ordinal.")
    # A lambda's reported label includes its line for navigation, but that line can change between baseline scans.
    return f"{_LAMBDA_POSITION.sub('<lambda>', symbol)}{_ORDINAL_SEPARATOR}{ordinal}"


def compute_identity_for(tool_language: str, rule_id: str, path: str, subject: str) -> str:
    """Hash the ratified identity under an explicit tool language.

    An explicit language token lets conformance tests compare identity digests across implementations.

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
    """Collect class, function and lambda declarations in one parsed file, innermost first.

    The runner uses the closest matching span to give findings on one declaration a shared position.
    Parsed spans reserve ordinal slots even for matching declarations that produced no findings.

    Args:
        tree: Parsed module AST, or ``None`` for a text file or a file that failed to parse.

    Returns:
        Declarations ordered innermost first, so the first span containing a line belongs to the closest declaration.
        With no tree or no declarations, the tuple is empty and the resolver uses the finding's reported line, or 1 if no positive line is available.
    """
    # Text-only and bounded scans fall back to reported locations because no parsed declaration spans are available.
    if tree is None:
        return ()
    spans: list[DeclarationSpan] = []
    pending = [(tree, "")]
    # Carry each enclosing name through the walk so methods with the same short name can keep separate reviews.
    while pending:
        node, prefix = pending.pop()
        # A finding on a decorator belongs to the same declaration as a finding on the definition line.
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            start = min((decorator.lineno for decorator in node.decorator_list), default=node.lineno)
            prefix = f"{prefix}.{node.name}" if prefix else node.name
            spans.append(DeclarationSpan(start, node.end_lineno or node.lineno, node.name, prefix))
        # Anonymous functions use an ordinal within their scope to keep the identity free of line numbers.
        elif isinstance(node, ast.Lambda):
            name = f"{prefix}.<lambda>" if prefix else "<lambda>"
            spans.append(DeclarationSpan(node.lineno, node.end_lineno or node.lineno, "<lambda>", name))
        pending.extend((child, prefix) for child in ast.iter_child_nodes(node))
    return tuple(sorted(spans, key=lambda span: (span.end - span.start, span.start)))


class DeclarationPositionResolver:
    """Place a finding on its declaration, and list every same-named declaration in its file.

    The list is what makes the ordinal count declarations rather than findings. Without it a clean earlier
    declaration takes no slot, so the day it first warns it takes the later declaration's ordinal and stored review.

    Stable contract: with the parsed spans present, a declaration's ordinal does not depend on which findings this run emitted.
    """

    def __init__(self, spans_by_file: Mapping[str, tuple[DeclarationSpan, ...]]) -> None:
        """Keep the parsed declarations of every file in this run.

        Args:
            spans_by_file: Declarations per display path, from :func:`declaration_spans`.

        Returns:
            None; the resolver retains the supplied mapping.
        """
        self._spans_by_file = spans_by_file

    def __call__(self, finding: Finding) -> int:
        """Find the declaration's first line so several findings on it can share one ordinal.
        When no declaration matches, use the reported location to rank the finding.

        Args:
            finding: The finding whose symbol names its declaration.

        Returns:
            The enclosing same-named declaration's start line, or the finding's positive line; 1 if its line is absent or nonpositive.
        """
        # Findings without a source line use the first position only for ranking their baseline identity.
        line = _default_declaration_position(finding)
        symbol = finding.symbol
        # Without a symbol there is no declaration to rank, and every symbol-less finding of one file shares a key anyway.
        if not symbol:
            return line
        enclosing = self._enclosing_matching_span(finding.file_path, symbol, line)
        # A warning anywhere inside the declaration spends its review at the same position.
        if enclosing is not None:
            return enclosing.start
        return line

    def same_named_positions(self, finding: Finding) -> tuple[int, ...]:
        """List the declaration positions that reserve ordinals for this finding's symbol.
        Include declarations that produced no findings so a previously reviewed sibling cannot pass its review to them.

        Args:
            finding: The finding whose symbol is looked up.

        Returns:
            Sorted unique start lines. An empty tuple contributes no extra positions to ordinal ranking.
            The result is empty for a missing symbol or when the file has no matching declarations.
        """
        symbol = finding.symbol
        # A finding without a symbol has no same-named declarations to rank against.
        if not symbol:
            return ()
        name = _LAMBDA_POSITION.sub("<lambda>", symbol)
        spans = self._spans_by_file.get(finding.file_path, ())
        # A report on `Widget.validate` must not use the review reserved for `Form.validate`.
        if "." in name:
            return tuple(sorted({span.start for span in spans if span.qualified_name == name}))
        # Match bare symbols only against siblings sharing the enclosing declaration's qualified scope.
        enclosing = self._enclosing_matching_span(finding.file_path, symbol, _default_declaration_position(finding))
        # A finding outside every declaration with its name ranks on its own line only.
        if enclosing is None:
            return ()
        return tuple(sorted({span.start for span in spans if span.name == name and span.qualified_name == enclosing.qualified_name}))

    def _enclosing_matching_span(self, path: str, symbol: str, line: int) -> DeclarationSpan | None:
        """Select the innermost matching declaration span enclosing the finding line.

        Args:
            path: File containing the declarations.
            symbol: Finding symbol, with any generated lambda marker.
            line: 1-based line number of the finding.

        Returns:
            The closest matching declaration span containing line, or None when no declaration matches.
        """
        name = _LAMBDA_POSITION.sub("<lambda>", symbol)
        spans = self._spans_by_file.get(path, ())
        # Qualified symbols match only declarations with the exact enclosing scope path.
        if "." in name:
            return next((span for span in spans if span.qualified_name == name and span.start <= line <= span.end), None)
        return next((span for span in spans if span.name == name and span.start <= line <= span.end), None)


def declaration_position_from_spans(spans_by_file: Mapping[str, tuple[DeclarationSpan, ...]]) -> DeclarationPositionResolver:
    """Build the resolver that maps a finding to the line its declaration begins on.

    The runner passes the result into baseline matching, so the ordinal counts declarations rather than lines:
    inserting code above a function moves its line and not its ordinal.

    Args:
        spans_by_file: Declarations per display path, from :func:`declaration_spans`.

    Returns:
        A resolver returning the enclosing declaration's start line, or the finding's positive line or 1 when no declaration matches.
        Its ranking list is empty for absent symbols. For a qualified symbol it lists positions in the matching scope.
    """
    return DeclarationPositionResolver(spans_by_file)


def _default_declaration_position(finding: Finding) -> int:
    """Use the finding's reported line to rank its declaration when the caller supplies no resolver.

    Args:
        finding: Finding whose reported line supplies the fallback declaration position.

    Returns:
        Its positive start line, or 1 when the line is absent or nonpositive.
    """
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
        declaration_position: Resolver for declaration start lines; None uses each finding's positive line or 1 when unavailable.

    Returns:
        One entry per input finding, aligned by index; ``None`` where the finding is sensitive or its symbol carries
        the ordinal separator, and so has no identity. A new identity for a finding without a symbol uses its normalized message.

    Raises:
        BaselineIdentityError: When a finding that needs a new identity has neither a symbol nor a nonempty message.
    """
    position = declaration_position or _default_declaration_position
    ordinals = _symbol_ordinals(findings, position)
    identities: list[FindingIdentity | None] = []
    for index, finding in enumerate(findings):
        # A sensitive finding is skipped before any hashing, so its contents never enter a stored identity; a symbol
        # carrying the ordinal separator is skipped too, since no subject built from it could be unambiguous.
        if not has_baseline_identity(finding):
            identities.append(None)
            continue
        # Reuse the name assigned over the whole scan so consumers such as the hook publish the same identity for a subset.
        if finding.baseline_identity is not None and finding.baseline_subject is not None:
            identities.append(
                FindingIdentity(
                    identity=finding.baseline_identity,
                    subject=finding.baseline_subject,
                    declaration_key=_stored_declaration_key(finding, finding.baseline_subject),
                )
            )
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

    Findings with the same file, symbol and resolved position share an ordinal. Distinct positions in that group get different ordinals.
    Ranks follow the current declaration order, so inserting or removing an earlier declaration can change later ordinals.

    Args:
        findings: Findings to rank in their input order; ineligible and symbol-less entries take no slot.
        position: Declaration-position resolver; its optional same_named_positions method adds parsed declarations without findings.

    Returns:
        Aligned one-based declaration ordinals, with 0 for entries that need no symbol ordinal.
    """
    positions_by_symbol: dict[tuple[str, str], set[int]] = {}
    same_named = getattr(position, "same_named_positions", None)
    # Reserve declaration slots before assigning ordinals so a clean sibling cannot shift later reviews.
    for finding in findings:
        # Findings without an eligible declaration cannot reserve a slot in this ranking.
        if finding.symbol and has_baseline_identity(finding):
            name = _LAMBDA_POSITION.sub("<lambda>", finding.symbol)
            positions = positions_by_symbol.setdefault((finding.file_path, name), set())
            positions.add(position(finding))
            # Reserve slots for same-named declarations the resolver supplies, including ones with no findings.
            if same_named is not None:
                positions.update(same_named(finding))

    ordinals: list[int] = []
    # Emit one ordinal per original finding so the runner can pair it with the right report row.
    for finding in findings:
        # Only findings eligible for a baseline identity with a symbol need ranking. The others keep their input slot with zero.
        if not finding.symbol or not has_baseline_identity(finding):
            ordinals.append(0)
            continue
        name = _LAMBDA_POSITION.sub("<lambda>", finding.symbol)
        ranked = sorted(positions_by_symbol[(finding.file_path, name)])
        ordinals.append(ranked.index(position(finding)) + 1)
    return tuple(ordinals)


def _stored_declaration_key(finding: Finding, subject: str) -> str:
    """Name the declaration of a finding that already carries its subject, without re-deriving a position.

    The subject already names one declaration, so two findings carrying one subject share a key and are counted,
    never reported as a collision.

    Args:
        finding: Finding whose symbol determines whether the key is file-level.
        subject: Already stored subject identifying the declaration for a symbol-bearing finding.

    Returns:
        The shared file-level key for a symbol-less finding, otherwise a key containing its stored subject.
    """
    if not finding.symbol:
        return "declaration:file"
    return f"declaration:subject:{subject}"


def _declaration_key(finding: Finding, position: Callable[[Finding], int]) -> str:
    """Name the declaration a finding sits on, for collision detection only.

    A file-level finding names no declaration at all, so every symbol-less occurrence shares one key and is
    matched by count; keying them by message would report two measurements of one file as an unresolvable collision.

    Args:
        finding: Finding whose symbol determines whether a declaration position is needed.
        position: Resolver called only for symbol-bearing findings to locate their declaration.

    Returns:
        The shared file-level key for a symbol-less finding, otherwise a key containing its resolved position.
    """
    if not finding.symbol:
        return "declaration:file"
    return f"declaration:{position(finding)}"
