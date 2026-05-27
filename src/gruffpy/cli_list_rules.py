"""``list-rules <rule_id>`` explain-mode helpers (text + JSON detail renderers).

Carved out of ``src/gruffpy/cli.py`` to keep that file under the
``size.file-length`` 1000-line error threshold and to keep ``_format_rule_detail``
and ``_option_type_label`` below the ``complexity.npath`` 500 ceiling.
"""

from __future__ import annotations

import difflib
import json
from typing import Any

import click

from gruffpy.rule.catalog import RELATED_RULES, RuleDocs, documentation_for_rule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry


def list_rules_detail(
    registry: RuleRegistry,
    rule_id: str,
    rule_format: str,
    write_stdout: Any,
) -> None:
    """Render the explain-mode detail view for a single rule, or raise on typo.

    Args:
        registry: Rule registry to look up the requested rule against.
        rule_id: Positional rule identifier supplied to ``list-rules``.
        rule_format: ``"json"`` for the structured payload; anything else
            renders the multi-line text shape.
        write_stdout: Sink callable matching ``cli._write_stdout``.

    Raises:
        click.ClickException: When ``rule_id`` is not in the registry; the
            exception message includes up to three ``difflib`` close-match
            suggestions when any are found.
    """
    if not registry.has(rule_id):
        all_ids = [rule.definition().id for rule in registry.all()]
        suggestions = difflib.get_close_matches(rule_id, all_ids, n=3)
        lines = [f"Unknown rule: {rule_id}"]
        if suggestions:
            lines.append(f"Did you mean: {', '.join(suggestions)}?")
        raise click.ClickException("\n".join(lines))
    definition = registry.get(rule_id).definition()
    docs = documentation_for_rule(rule_id)
    related = RELATED_RULES.get(rule_id, ())
    if rule_format == "json":
        write_stdout(json.dumps(_rule_detail_payload(definition, docs, related), indent=4))
        write_stdout("\n")
        return
    write_stdout(_format_rule_detail(definition, docs, related))


def _rule_detail_payload(
    definition: RuleDefinition,
    docs: RuleDocs,
    related: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "id": definition.id,
        "name": definition.name,
        "pillar": definition.pillar.value,
        "tier": definition.tier.value,
        "defaultSeverity": definition.default_severity.value,
        "confidence": definition.confidence.value,
        "defaultEnabled": definition.default_enabled,
        "thresholds": dict(definition.default_thresholds),
        "options": dict(definition.default_options),
        "documentation": docs.to_payload(),
        "relatedRules": list(related),
    }


def _format_rule_detail(
    definition: RuleDefinition,
    docs: RuleDocs,
    related: tuple[str, ...],
) -> str:
    sections: list[list[str]] = [_rule_detail_header(definition)]
    sections.extend(_rule_detail_prose_block(("Rationale", docs.rationale)))
    sections.extend(_rule_detail_prose_block(("Fix guidance", docs.fix_guidance)))
    sections.extend(_rule_detail_prose_block(("Bad example", docs.bad_example)))
    sections.extend(_rule_detail_prose_block(("Good example", docs.good_example)))
    sections.extend(_rule_detail_options_block(definition, docs))
    sections.extend(_rule_detail_escape_hatches_block(definition.id, docs))
    sections.extend(_rule_detail_prose_block(("Confidence", docs.confidence_rationale)))
    sections.append(_rule_detail_false_positives(docs))
    sections.append(_rule_detail_related(related))
    return "\n".join(line for section in sections for line in section) + "\n"


def _rule_detail_prose_block(field: tuple[str, str]) -> list[list[str]]:
    header, body = field
    return [_rule_detail_prose(header, body)] if body else []


def _rule_detail_options_block(definition: RuleDefinition, docs: RuleDocs) -> list[list[str]]:
    return [_rule_detail_options(definition, docs)] if definition.default_options else []


def _rule_detail_escape_hatches_block(rule_id: str, docs: RuleDocs) -> list[list[str]]:
    return [_rule_detail_escape_hatches(rule_id, docs)] if docs.config_keys else []


def _rule_detail_header(definition: RuleDefinition) -> list[str]:
    return [
        f"Rule: {definition.id}",
        f"  Name:      {definition.name}",
        f"  Pillar:    {definition.pillar.value}",
        f"  Tier:      {definition.tier.value}",
        f"  Severity:  {definition.default_severity.value} (default)",
        f"  Confidence: {definition.confidence.value}",
        f"  Enabled by default: {'yes' if definition.default_enabled else 'no'}",
    ]


def _rule_detail_prose(header: str, body: str) -> list[str]:
    return ["", f"{header}:", f"  {body}"]


def _rule_detail_options(definition: RuleDefinition, docs: RuleDocs) -> list[str]:
    rows = list(definition.default_options.items())
    name_width = max(len(name) for name, _ in rows)
    type_width = max(len(_option_type_label(value)) for _, value in rows)
    lines = ["", "Default options:"]
    for name, value in rows:
        description = docs.option_descriptions.get(name, "")
        line = f"  {name:<{name_width}}  {_option_type_label(value):<{type_width}}  {description}"
        lines.append(line.rstrip())
    return lines


_OPTION_TYPE_LABELS: tuple[tuple[type, str], ...] = (
    (bool, "bool"),
    (int, "int"),
    (float, "float"),
    (str, "str"),
    (list, "list"),
    (dict, "dict"),
)


def _option_type_label(value: Any) -> str:
    for cls, label in _OPTION_TYPE_LABELS:
        if isinstance(value, cls):
            return label
    return type(value).__name__


_ESCAPE_HATCH_NOTES: tuple[tuple[str, str, str], ...] = (
    ("suffix", ".enabled", "set false to disable this rule entirely"),
    ("suffix", ".severity", "override severity (advisory / warning / error)"),
    ("suffix", ".threshold", "override the single numeric threshold"),
    ("contains", ".thresholds.", "override one named numeric threshold"),
    ("contains", ".options.", "override one named option default"),
)


def _escape_hatch_note(row: str) -> str:
    for match_kind, pattern, note in _ESCAPE_HATCH_NOTES:
        if match_kind == "suffix" and row.endswith(pattern):
            return note
        if match_kind == "contains" and pattern in row:
            return note
    return ""


def _rule_detail_escape_hatches(rule_id: str, docs: RuleDocs) -> list[str]:
    rows = [f"rules.{rule_id}.{key}" for key in docs.config_keys]
    rows.append(f"rules.{rule_id}.enabled")
    name_width = max(len(row) for row in rows)
    lines = ["", "Escape hatches:"]
    for row in rows:
        lines.append(f"  {row:<{name_width}}  {_escape_hatch_note(row)}".rstrip())
    return lines


def _rule_detail_false_positives(docs: RuleDocs) -> list[str]:
    lines = ["", "Common false-positive shapes:"]
    if not docs.false_positive_shapes:
        lines.append("  (none documented yet)")
        return lines
    for fp in docs.false_positive_shapes:
        lines.append(f"  - {fp.shape}")
        lines.append(f"    Mitigation: {fp.mitigation}")
    return lines


def _rule_detail_related(related: tuple[str, ...]) -> list[str]:
    lines = ["", "Related rules:"]
    if not related:
        lines.append("  (none)")
        return lines
    for rule_id in related:
        lines.append(f"  {rule_id}")
    return lines
