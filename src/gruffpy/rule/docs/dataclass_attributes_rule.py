"""``docs.dataclass-attributes`` — public dataclass payloads need field context."""

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
        allow_bullets = bool(
            settings.options.get("allow_bullets", definition.default_options["allow_bullets"])
        )
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
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return fallback


def _dataclass_fields(node: ast.ClassDef) -> tuple[str, ...]:
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
    if not docstring:
        return ()
    field_set = set(fields)
    documented: set[str] = set()
    in_attribute_section = False
    for raw_line in docstring.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        sphinx_match = _SPHINX_FIELD_PATTERN.search(stripped)
        if sphinx_match and sphinx_match.group(1) in field_set:
            documented.add(sphinx_match.group(1))
        if stripped.rstrip(":").lower() in {"attributes", "attrs"}:
            in_attribute_section = True
            continue
        if in_attribute_section:
            if not stripped:
                continue
            if not raw_line.startswith((" ", "\t")) and not set(stripped) <= {"-"}:
                in_attribute_section = False
                continue
            match = _FIELD_PATTERN.match(stripped)
            if match and match.group(1) in field_set:
                documented.add(match.group(1))
        if allow_bullets:
            bullet_match = _BULLET_FIELD_PATTERN.match(stripped)
            if bullet_match and bullet_match.group(1) in field_set:
                documented.add(bullet_match.group(1))
    return tuple(field for field in fields if field in documented)


def _dataclass_attributes_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
    *,
    fields: tuple[str, ...],
    documented_fields: tuple[str, ...],
) -> Finding:
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
        remediation=(
            "Add an Attributes section or field bullet list explaining the dataclass "
            "payload fields."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "fieldCount": len(fields),
            "documentedFields": list(documented_fields),
            "missingFields": list(missing_fields),
        },
    )
