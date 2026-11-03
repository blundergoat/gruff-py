"""``docs.dataclass-attributes`` - public dataclass payloads need field context."""

import ast
import re
from typing import Any

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import has_dataclass_decorator
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring
from gruffpy.rule.docs._helpers import is_public
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_FIELD_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::|\(|-|$)")
_SPHINX_FIELD_PATTERN = re.compile(r":(?:ivar|cvar)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:")
_BULLET_FIELD_PATTERN = re.compile(r"^\s*[-*]\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s*(?::|-)")


class DataclassAttributesRule(Rule):
    """Detect public dataclasses whose payload fields are not documented."""

    ID = "docs.dataclass-attributes"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the dataclass attribute documentation rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dataclass attributes",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_options={
                "min_fields": 3,
                "require_all_fields": False,
                "allow_bullets": True,
            },
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze dataclass definitions for missing payload documentation.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with dataclass documentation options.

        Returns:
            Findings for public dataclasses with undocumented field payloads.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_fields = _positive_int(
            settings.options.get("min_fields", definition.default_options["min_fields"]),
            fallback=int(definition.default_options["min_fields"]),
        )
        require_all_fields = bool(
            settings.options.get(
                "require_all_fields",
                definition.default_options["require_all_fields"],
            )
        )
        allow_bullets = bool(settings.options.get("allow_bullets", definition.default_options["allow_bullets"]))
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            fields = _dataclass_fields(node)
            if not _should_report(
                node,
                fields=fields,
                min_fields=min_fields,
                require_all_fields=require_all_fields,
                allow_bullets=allow_bullets,
            ):
                continue
            findings.append(
                _dataclass_attributes_finding(
                    unit,
                    definition,
                    node,
                    fields=fields,
                    documented_fields=_documented_fields(
                        extract_docstring(node),
                        fields=fields,
                        allow_bullets=allow_bullets,
                    ),
                )
            )
        return findings


def _positive_int(value: Any, *, fallback: int) -> int:
    """Accept a configured option value only when it is a positive integer, otherwise use the fallback.

    Args:
        value: Raw option value read from the rule settings; booleans, non-integers, zero and negative numbers are rejected.
        fallback: Value returned when value is rejected; analyse passes the default min_fields.

    Returns:
        value when it is a non-bool int greater than zero, otherwise fallback.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _dataclass_fields(node: ast.ClassDef) -> tuple[str, ...]:
    """Collect the public names a class body assigns directly, skipping annotations whose leaf name is ClassVar.

    Only top-level body statements count: annotated assignments to a bare name, with or without a value, and plain assignments with a single bare-name
    target. Names that is_public rejects are dropped. A quoted ClassVar annotation is not skipped, because _annotation_leaf returns an empty name for
    string annotations. This function does not check for a dataclass decorator; _should_report does that.

    Args:
        node: Class definition whose direct body statements are scanned.

    Returns:
        Field names in body order, with a name listed once per qualifying assignment; empty when no direct body statement qualifies.
    """
    fields: list[str] = []
    for stmt in node.body:
        field_name: str | None = None
        annotation: ast.AST | None = None
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            field_name = stmt.target.id
            annotation = stmt.annotation
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                field_name = target.id
        if field_name is None or not is_public(field_name):
            continue
        if annotation is not None and _annotation_leaf(annotation) == "ClassVar":
            continue
        fields.append(field_name)
    return tuple(fields)


def _annotation_leaf(annotation: ast.AST) -> str:
    """Reduce an annotation to its trailing name so ClassVar is recognised bare, qualified or subscripted.

    Args:
        annotation: Annotation expression taken from an annotated assignment in the class body.

    Returns:
        The identifier for a Name, the attribute name for an Attribute, the leaf of the subscripted value for a Subscript, and an empty string for any
        other expression, including a string annotation.
    """
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    if isinstance(annotation, ast.Subscript):
        return _annotation_leaf(annotation.value)
    return ""


def _should_report(
    node: ast.ClassDef,
    *,
    fields: tuple[str, ...],
    min_fields: int,
    require_all_fields: bool,
    allow_bullets: bool,
) -> bool:
    """Decide whether a public dataclass- or attrs-decorated class with enough fields lacks field documentation.

    A class is eligible when is_public accepts its name, has_dataclass_decorator matches the leaf name of one of its decorators, and it has at least
    min_fields fields. An eligible class is reported when its docstring documents none of its fields, or, with require_all_fields set, when the
    documented set differs from the field set.

    Args:
        node: Class definition under test; its name, decorators and docstring are read.
        fields: Public field names collected by _dataclass_fields for this class.
        min_fields: Smallest field count that makes the class eligible; a class with fewer fields is never reported.
        require_all_fields: When True, a class with some but not all fields documented is also reported; when False, documenting any one field is
            enough.
        allow_bullets: Passed to _documented_fields; when False, bullet lines do not count as field documentation.

    Returns:
        True when the class should produce a finding, otherwise False.
    """
    if not is_public(node.name) or not has_dataclass_decorator(node) or len(fields) < min_fields:
        return False
    documented_fields = _documented_fields(
        extract_docstring(node),
        fields=fields,
        allow_bullets=allow_bullets,
    )
    if not documented_fields:
        return True
    return require_all_fields and set(documented_fields) != set(fields)


def _documented_fields(
    docstring: str | None,
    *,
    fields: tuple[str, ...],
    allow_bullets: bool,
) -> tuple[str, ...]:
    """Return fields documented by Sphinx entries, Attributes sections, or bullets.

    The three syntaxes are collected independently so the section-tracking
    state for Google-style ``Attributes:`` blocks does not obscure the simpler
    Sphinx and bullet matchers.

    Args:
        docstring: Raw class docstring from extract_docstring; None or an empty string yields no documented fields.
        fields: Field names to look for; names outside this tuple are ignored and the result follows its order.
        allow_bullets: When False, the bullet matcher is skipped and only Sphinx entries and attributes sections count.

    Returns:
        Members of fields found by any enabled matcher, in the order of fields; empty when the docstring is missing or matches none of them.
    """
    if not docstring:
        return ()
    field_set = set(fields)
    documented = set(_sphinx_documented_fields(docstring, field_set))
    documented.update(_attribute_section_fields(docstring, field_set))
    if allow_bullets:
        documented.update(_bullet_documented_fields(docstring, field_set))
    return tuple(field for field in fields if field in documented)


def _sphinx_documented_fields(docstring: str, field_set: set[str]) -> tuple[str, ...]:
    """Collect field names declared by ``:ivar name:`` or ``:cvar name:`` entries anywhere in a docstring line.

    Args:
        docstring: Non-empty raw docstring text, scanned line by line.
        field_set: Names that count as fields; a matched name outside the set is ignored.

    Returns:
        Matched field names in docstring order, at most one per line because only the first entry on a line is read, and repeated when a field is the
        first entry on several lines; empty when no line's first entry names a field.
    """
    documented: list[str] = []
    for raw_line in docstring.splitlines():
        field = _matched_field(_SPHINX_FIELD_PATTERN.search(raw_line.strip()), field_set)
        if field is not None:
            documented.append(field)
    return tuple(documented)


def _attribute_section_fields(docstring: str, field_set: set[str]) -> tuple[str, ...]:
    """Collect field names that start a line inside an attributes section of a docstring.

    _is_attribute_section_header opens the section and _is_attribute_section_exit closes it; the closing line itself is not checked for a field, blank
    lines inside the section are skipped, and a later header line reopens it. A line counts when _FIELD_PATTERN matches a field name at the start of
    the stripped line followed by a colon, an opening parenthesis, a hyphen or the end of the line.

    Args:
        docstring: Non-empty raw docstring text, scanned line by line.
        field_set: Names that count as fields; a matched name outside the set is ignored.

    Returns:
        Matched field names in docstring order, repeated when a field is listed more than once; empty when no section line names a field.
    """
    documented: list[str] = []
    in_attribute_section = False
    for raw_line in docstring.splitlines():
        stripped = raw_line.rstrip().strip()
        if _is_attribute_section_header(stripped):
            in_attribute_section = True
            continue
        if not in_attribute_section or not stripped:
            continue
        if _is_attribute_section_exit(raw_line, stripped):
            in_attribute_section = False
            continue
        field = _matched_field(_FIELD_PATTERN.match(stripped), field_set)
        if field is not None:
            documented.append(field)
    return tuple(documented)


def _bullet_documented_fields(docstring: str, field_set: set[str]) -> tuple[str, ...]:
    """Collect field names that open a hyphen or asterisk bullet line and are followed by a colon or hyphen.

    The name may be wrapped in single backticks. _documented_fields calls this only when allow_bullets is set.

    Args:
        docstring: Non-empty raw docstring text, scanned line by line.
        field_set: Names that count as fields; a matched name outside the set is ignored.

    Returns:
        Matched field names in docstring order, repeated when a field has more than one bullet; empty when no bullet names a field.
    """
    documented: list[str] = []
    for raw_line in docstring.splitlines():
        field = _matched_field(_BULLET_FIELD_PATTERN.match(raw_line.strip()), field_set)
        if field is not None:
            documented.append(field)
    return tuple(documented)


def _is_attribute_section_header(stripped: str) -> bool:
    """Recognise a docstring line that opens an attributes section.

    Args:
        stripped: Docstring line with surrounding whitespace removed.

    Returns:
        True when the line, with trailing colons removed and lowercased, is attributes or attrs.
    """
    return stripped.rstrip(":").lower() in {"attributes", "attrs"}


def _is_attribute_section_exit(raw_line: str, stripped: str) -> bool:
    """Decide whether a non-blank line inside an attributes section ends that section.

    Args:
        raw_line: Line as it appears in the raw docstring, tested for leading indentation.
        stripped: The same line with surrounding whitespace removed; the caller never passes an empty value.

    Returns:
        True when the raw line starts with neither a space nor a tab and is not made only of hyphens, so an unindented hyphen underline keeps the
        section open.
    """
    return not raw_line.startswith((" ", "\t")) and not set(stripped) <= {"-"}


def _matched_field(match: re.Match[str] | None, field_set: set[str]) -> str | None:
    """Turn a field-pattern match into a field name only when the captured name is one of the class's fields.

    Args:
        match: Result of applying one of the field patterns to a docstring line; None when the line did not match.
        field_set: Names that count as fields.

    Returns:
        The first capture group when it names a field; None when there is no match or the captured name is outside field_set.
    """
    if match is None:
        return None
    field = match.group(1)
    if field not in field_set:
        return None
    return field


def _dataclass_attributes_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    *,
    fields: tuple[str, ...],
    documented_fields: tuple[str, ...],
) -> Finding:
    """Build the finding for a reported class, recording its documented and missing public fields.

    The message names the qualified symbol and the total public field count from fields, not the missing count. Metadata records fieldCount,
    documentedFields and missingFields, where missingFields lists the fields absent from documented_fields in field order. Severity, pillar, tier and
    confidence come from definition, and the finding spans node from its lineno to its end_lineno.

    Args:
        unit: Analysed file whose display path is recorded on the finding.
        definition: Rule definition supplying the rule id, default severity, pillar, tier, confidence and secondary pillars.
        node: Reported class; supplies the line span and, with its parent chain, the qualified symbol.
        fields: All public field names of the class; its length is the count in the message and in fieldCount.
        documented_fields: Field names found documented in the class docstring; recorded as documentedFields and excluded from missingFields.

    Returns:
        The populated Finding for the class.
    """
    symbol = qualified_symbol(node, parent_chain(node))
    missing_fields = tuple(field for field in fields if field not in set(documented_fields))
    return Finding(
        rule_id=definition.id,
        message=f"Dataclass {symbol!r} has {len(fields)} public fields without payload docs.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Add an Attributes section or field bullet list explaining the dataclass payload fields."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "fieldCount": len(fields),
            "documentedFields": list(documented_fields),
            "missingFields": list(missing_fields),
        },
    )
