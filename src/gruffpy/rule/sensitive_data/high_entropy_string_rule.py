"""Report long, random-looking values that users should review for embedded credentials.

The detector scans source text with configurable length and entropy thresholds, defaulting to 32 characters and 4.2 bits.
Public shapes are checked in full; quoted values keep dots and padding so a readable prefix cannot hide an opaque suffix.
Unquoted assignments split at the equals sign so a key cannot inflate its value.
"""

import os
import re
import tomllib
from pathlib import PurePosixPath

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.sensitive_data._entropy_public_shapes import is_public_entropy_shape, is_public_entropy_url
from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    fixed_preview,
    is_documented_sample,
    shannon_entropy,
)
from gruffpy.rule.sensitive_data.api_key_pattern_rule import contains_provider_api_key

# Unquoted assignments split at ``=``: joined, ``AWS_DEFAULT_REGION=ap-southeast-2`` measured 33 characters
# at 4.62 bits, while neither half is a candidate. Complete quoted values retain dots and padding so a
# public prefix cannot suppress an opaque suffix inside the same literal.
_CANDIDATE_PATTERN = re.compile(r"""(?P<quote>["'])(?P<quoted>[A-Za-z0-9+/=._-]+)(?P=quote)|(?P<bare>[A-Za-z0-9+/_-]+)""")
_PEM_ARMOUR_OPENING = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
# Any opening or closing marker, so a block can end only at the next one.
_PEM_ARMOUR_MARKER = re.compile(r"-----(BEGIN|END) ([A-Z0-9 ]+)-----")
# A PEM body's lines break at real line breaks and at the escaped ones a string literal spells. Each line then loses
# its concatenation operators, and its quotes, commas, brackets, comment stars and ASCII whitespace, before
# _PEM_BODY_LINE judges what is left. The operator pattern looks around one character so it stays linear.
_PEM_BODY_LINE_BREAKS = re.compile(r"\n|\\[nrt]")
_PEM_BODY_OPERATORS = re.compile(r"(?<=[ \t\r\f\x0b])[+.]|[+.](?=[ \t\r\f\x0b])")
_PEM_BODY_QUOTING = re.compile(r"[ \t\r\f\x0b\"'`,;()\[\]{}#*\\]")
_PEM_BODY_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}|=[A-Za-z0-9+/]{4}|(?:Version|Comment|Hash|Charset|MessageID|Proc-Type|DEK-Info):.*")
_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
# pyproject.toml settings that hold repository paths: coverage path lists and ty exclusions by table and key, and ruff
# per-file-ignores keys. The list is closed, so every other table or key keeps its strings under the entropy rule.
_PYPROJECT_PATH_LISTS: dict[str, tuple[str, ...]] = {
    "tool.coverage.run": ("source", "omit", "include"),
    "tool.coverage.report": ("omit", "include"),
    "tool.ty.src": ("exclude",),
}
_PYPROJECT_PATH_KEY_TABLES = frozenset({"tool.ruff.lint.per-file-ignores"})
# A key assignment starting a line, bare or quoted, such as ``omit = [`` or ``"docs/a.py" = ["E501"]``.
_TOML_KEY_ASSIGNMENT = re.compile(r"""^[ \t]*(?P<key>"[^"\n]*"|'[^'\n]*'|[A-Za-z0-9_-]+)[ \t]*=""", re.MULTILINE)
# A standard table header line such as ``[tool.coverage.run]``; array-of-tables headers never hold these settings.
_TOML_TABLE_HEADER = re.compile(r"^[ \t]*\[(?!\[)([^\[\]\n]+)\][ \t]*(?:#[^\n]*)?$", re.MULTILINE)


class HighEntropyStringRule(SourceTextRule):
    """Detect long base64-alphabet strings above the secret entropy threshold.

    Users see a review finding for unknown random-looking literals after common benign shapes and
    provider keys are removed, with no candidate-derived text included in the preview.
    """

    ID = "sensitive-data.high-entropy-string"

    def definition(self) -> RuleDefinition:
        """Expose the enabled warning rule and its configurable thresholds to users inspecting the rule catalogue.

        Returns:
            Rule metadata with medium confidence and the family defaults of 32 characters and 4.2 bits.
        """
        return RuleDefinition(
            id=self.ID,
            name="High-entropy string",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"minLength": 32, "entropy": 4.2},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report possible credentials after public-shape exclusions and the user's configured entropy thresholds.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context supplying the ``minLength`` and ``entropy`` thresholds.

        Returns:
            One warning per qualifying value; an empty list means none needed review under this rule.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        # A zero-length candidate is no string at all, so a configured minLength below 1 still needs one character.
        min_length = max(1, int(settings.numeric_threshold("minLength")))
        entropy_threshold = settings.numeric_threshold("entropy")
        findings: list[Finding] = []
        public_spans = _public_armour_spans(unit.source) + _public_url_spans(unit.source)
        path_spans = _pyproject_path_spans(unit)
        # Each random-looking literal is assessed independently so users can triage its source line.
        for candidate_match in _CANDIDATE_PATTERN.finditer(unit.source):
            secret_candidate = candidate_match.group("quoted") or candidate_match.group("bare")
            # A value below the user's length threshold does not justify an entropy warning.
            if len(secret_candidate) < min_length:
                continue
            # Proven public PEM material and complete public endpoints do not need the user's entropy review.
            if any(start <= candidate_match.start() < end for start, end in public_spans):
                continue
            # Known benign shapes, vendor-documented samples and listed pyproject settings naming an existing project path
            # stay out of the report before the entropy threshold is applied.
            if (
                _is_benign_literal(secret_candidate)
                or is_documented_sample(secret_candidate)
                or _is_listed_project_path(unit, context.project_root, path_spans, candidate_match)
            ):
                continue
            # Lower-entropy text lacks enough secret signal to justify a user-facing warning.
            if shannon_entropy(secret_candidate) < entropy_threshold:
                continue
            line = unit.source.count("\n", 0, candidate_match.start()) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="High-entropy string - possible secret literal.",
                    file_path=unit.file.display_path,
                    line=line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "If this is genuinely a secret, rotate it and move it out of "
                        "the repository. If it is benign, confirm that judgment during review; "
                        "secret-derived preview allowlisting is not supported."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    # Report only the fixed marker; the value's length and entropy would reveal information about the possible secret.
                    metadata={"preview": fixed_preview()},
                ),
            )
        return findings


def _public_url_spans(source: str) -> list[tuple[int, int]]:
    """Locate complete public endpoints and bare revision or portal references before punctuation splitting.

    Args:
        source: Source text; partial URLs and links inside larger strings grant no exception.

    Returns:
        Proven source spans; an empty list leaves all candidate tokens eligible for scanning.
    """
    spans: list[tuple[int, int]] = []
    quoted_spans: list[tuple[int, int]] = []
    # Consume enclosing strings, including multiline documentation, before considering bare references.
    quoted_values = (
        r"""(?<![\\])(?:(?P<block_quote>\"\"\"|''')(?P<block_url>(?:\\[\s\S]|(?!(?P=block_quote))[^\\])*)(?P=block_quote)|"""
        r"""(?P<quote>["'])(?P<url>(?:\\[^\r\n]|(?!(?P=quote))[^\\\r\n])*)(?P=quote))"""
    )
    for literal in re.finditer(quoted_values, source):
        quoted_spans.append(literal.span())
        # Empty strings and the unmatched quote alternative supply no public endpoint.
        complete_url = literal.group("block_url") or literal.group("url") or ""
        # Only the entire quoted endpoint can excuse the user's otherwise secret-looking tokens.
        if is_public_entropy_url(complete_url):
            spans.append(literal.span())
    # A comment may link to a public revision or the application's portal settings.
    for reference in re.finditer(r"""(?:^|[\s(<])(?P<url>https://[^\s"'`<>]+)""", source):
        url = reference.group("url")
        start, end = reference.span("url")
        # An enclosing string or any extra URL component prevents a bare-reference exception.
        if (
            not any(left <= start < right for left, right in quoted_spans)
            and url.startswith(("https://github.com/", "https://entra.microsoft.com/"))
            and is_public_entropy_url(url)
        ):
            spans.append((start, end))
    return spans


def _public_armour_spans(source: str) -> list[tuple[int, int]]:
    """Locate public PEM material that users need not review as an entropy warning.
    Only a matching next closing marker and a PEM-shaped body grant the exception; private-key material remains scannable.

    Args:
        source: The file text being scanned.

    Returns:
        Half-open public-block spans; an empty list leaves all source eligible for scanning.
    """
    spans: list[tuple[int, int]] = []
    # Check each possible block so public certificates can stay quiet without concealing nearby credentials.
    for opening in _PEM_ARMOUR_OPENING.finditer(source):
        label = opening.group(1)
        # Private-key material always remains available to the normal secret checks.
        if "PRIVATE" in label:
            continue
        closing = _PEM_ARMOUR_MARKER.search(source, opening.end())
        # An absent or mismatched closing marker cannot establish a public block.
        if closing is None or closing.group(1) != "END" or closing.group(2) != label:
            continue
        # Only PEM-shaped content may skip scanning; marker constants surrounding ordinary code grant no exception.
        if _is_pem_shaped(source[opening.end() : closing.start()]):
            spans.append((opening.start(), closing.end()))
    return spans


def _pyproject_path_spans(unit: AnalysisUnit) -> list[tuple[int, int, frozenset[str]]]:
    """Map each listed pyproject table's source span to the strings its path settings hold.

    Args:
        unit: Scanned file; only a ``pyproject.toml`` whose TOML parses can supply path settings.

    Returns:
        Half-open spans of each listed setting's value, or of each per-file-ignores key, with the strings the parsed
        document holds there; an empty list grants no path exception.
    """
    # Other file names and TOML that does not parse keep every string under the entropy rule.
    if PurePosixPath(unit.file.display_path).name != "pyproject.toml":
        return []
    try:
        document = tomllib.loads(unit.source)
    except tomllib.TOMLDecodeError:
        return []
    headers = list(_TOML_TABLE_HEADER.finditer(unit.source))
    spans: list[tuple[int, int, frozenset[str]]] = []
    # A table's body runs from its header to the next header, so each setting is judged inside the table that holds it.
    for index, header in enumerate(headers):
        name = ".".join(part.strip().strip("\"'") for part in header.group(1).split("."))
        table = _toml_table(document, name)
        if table is not None and (name in _PYPROJECT_PATH_LISTS or name in _PYPROJECT_PATH_KEY_TABLES):
            body_end = headers[index + 1].start() if index + 1 < len(headers) else len(unit.source)
            spans.extend(_setting_spans(unit.source, name, table, header.end(), body_end))
    return spans


def _toml_table(document: dict[str, object], dotted_name: str) -> dict[str, object] | None:
    """Return the parsed table at a dotted name.

    Args:
        document: Parsed TOML document.
        dotted_name: Table name such as ``tool.coverage.run``.

    Returns:
        The table, or None when a step is missing or is not a table.
    """
    table: object = document
    # Walk the dotted name; a missing or non-table step leaves nothing to collect.
    for part in dotted_name.split("."):
        table = table.get(part) if isinstance(table, dict) else None
    return table if isinstance(table, dict) else None


def _setting_spans(source: str, name: str, table: dict[str, object], body_start: int, body_end: int) -> list[tuple[int, int, frozenset[str]]]:
    """Locate the listed path settings inside one table body.

    Args:
        source: The pyproject text.
        name: Dotted table name, one of the listed path tables.
        table: The parsed table, which supplies the strings each setting really holds.
        body_start: Offset just past the table header.
        body_end: Offset of the next header or the end of the file.

    Returns:
        A per-file-ignores key's own quoted span, or a listed array setting's value span, with its parsed strings.
    """
    assignments = list(_TOML_KEY_ASSIGNMENT.finditer(source, body_start, body_end))
    spans: list[tuple[int, int, frozenset[str]]] = []
    # Each assignment is judged by its own key, so an unlisted key's value never borrows a listed key's paths.
    for position, assignment in enumerate(assignments):
        key = assignment.group("key").strip("\"'")
        if name in _PYPROJECT_PATH_KEY_TABLES:
            # A per-file-ignores key names its path; only a parsed key's own quoted text can carry the exception.
            if key in table:
                spans.append((assignment.start("key"), assignment.end("key"), frozenset({key})))
            continue
        entries = table.get(key)
        if key in _PYPROJECT_PATH_LISTS[name] and isinstance(entries, list):
            value_end = assignments[position + 1].start() if position + 1 < len(assignments) else body_end
            spans.append((assignment.end(), value_end, frozenset(entry for entry in entries if isinstance(entry, str))))
    return spans


def _is_listed_project_path(
    unit: AnalysisUnit,
    project_root: str,
    path_spans: list[tuple[int, int, frozenset[str]]],
    candidate_match: re.Match[str],
) -> bool:
    """Report whether a quoted string is a listed pyproject path setting naming an existing project path.

    Contract invariant: the parsed setting role and an existing path are both required, so a table name, a key or a
    path-like shape alone never silences a possible secret.

    Args:
        unit: Scanned file whose project-relative folder anchors the path.
        project_root: Absolute project root that the path must stay inside.
        path_spans: Listed table spans and the strings their path settings hold.
        candidate_match: Candidate token; only a whole quoted string can be a setting value.

    Returns:
        True only when the string belongs to a listed setting of the table holding it and names an existing project path.
    """
    candidate = candidate_match.group("quoted")
    offset = candidate_match.start()
    # An unquoted token, or a string outside the listed settings of its own table, has no path role.
    if not candidate or not any(start <= offset < end and candidate in strings for start, end, strings in path_spans):
        return False
    return _is_existing_project_path(project_root, unit.file.display_path, candidate)


def _is_existing_project_path(project_root: str, display_path: str, relative_path: str) -> bool:
    """Report whether a path relative to a config file's folder reaches an existing project path without a symlink.

    Args:
        project_root: Absolute project root that the path must stay inside.
        display_path: Project-relative path of the config file whose folder anchors the relative path.
        relative_path: Setting value; an absolute path never qualifies.

    Returns:
        True only when every step stays inside the project, none is a symlink and the final file or folder exists.
    """
    # An absolute setting or a config file outside the project has no project-relative anchor.
    if relative_path.startswith("/") or PurePosixPath(display_path).is_absolute():
        return False
    segments: list[str] = []
    path = project_root
    # Check each traversed component before a parent step can discard it.
    for segment in [*PurePosixPath(display_path).parent.parts, *relative_path.split("/")]:
        if not os.path.isdir(path):
            return False
        if segment in ("", "."):
            continue
        if segment == "..":
            if not segments:
                return False
            segments.pop()
            path = os.path.dirname(path)
            continue
        segments.append(segment)
        path = os.path.join(path, segment)
        if os.path.islink(path):
            return False
    return bool(segments) and os.path.exists(path)


def _is_pem_shaped(body: str) -> bool:
    """Report whether every line between two markers is base64, a PGP checksum, an armour header or empty.

    Args:
        body: The text between an opening marker and its closing marker.

    Returns:
        False when any line, once its string quoting is stripped, is code, a placeholder or prose.
    """
    # Splitting at escaped line breaks too keeps a one-line block's header from vouching for the rest of the line.
    for segment in _PEM_BODY_LINE_BREAKS.split(body):
        line = _PEM_BODY_QUOTING.sub("", _PEM_BODY_OPERATORS.sub("", segment))
        # Empty body lines carry no value, but any non-PEM content keeps the whole region scannable.
        if line and _PEM_BODY_LINE.fullmatch(line) is None:
            return False
    return True


def _is_benign_literal(candidate: str) -> bool:
    """Best-effort screen against common false-positive shapes; the candidate already meets ``minLength``."""
    # The family floor keeps digit-free identifiers out of the user's entropy warnings.
    if not _has_letter_and_digit(candidate):
        return True
    # A provider-specific detector owns this value, avoiding a duplicate generic warning.
    if contains_provider_api_key(candidate):
        return True
    # A complete public shape can skip entropy scoring; a matching prefix alone cannot.
    if is_public_entropy_shape(candidate):
        return True
    return _HEX_RE.match(candidate) is not None and len(candidate) < 40


def _has_letter_and_digit(candidate: str) -> bool:
    """Require both a letter and a digit before presenting a literal as a possible credential.
    This family-wide floor keeps digit-free identifiers out of the user's entropy warnings.

    Args:
        candidate: The literal being classified.

    Returns:
        True when the literal holds both a letter and a digit.
    """
    has_letter = any("a" <= character <= "z" or "A" <= character <= "Z" for character in candidate)
    return has_letter and any("0" <= character <= "9" for character in candidate)
