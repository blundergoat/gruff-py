"""Generate and check the committed built-in rule documentation."""

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from gruffpy.finding.pillar import Pillar
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry

_PILLAR_ORDER: tuple[Pillar, ...] = (
    Pillar.SIZE,
    Pillar.COMPLEXITY,
    Pillar.MAINTAINABILITY,
    Pillar.DEAD_CODE,
    Pillar.NAMING,
    Pillar.DOCUMENTATION,
    Pillar.SECURITY,
    Pillar.SENSITIVE_DATA,
    Pillar.TEST_QUALITY,
    Pillar.DESIGN,
)

_PILLAR_NOTES = {
    Pillar.SIZE: "File, class, function, parameter, method, and attribute size",
    Pillar.COMPLEXITY: "Cyclomatic, cognitive, Halstead, nesting, and NPATH",
    Pillar.MAINTAINABILITY: "Maintainability index rule emits under this pillar",
    Pillar.DEAD_CODE: "Unused and waste-oriented rules",
    Pillar.NAMING: "Intent-layer names; PEP 8 case style stays with ruff",
    Pillar.DOCUMENTATION: (
        "Docstring presence and quality, stale docs, TODO density, README presence"
    ),
    Pillar.SECURITY: "Heuristic AST-level dangerous patterns",
    Pillar.SENSITIVE_DATA: "Secret, key, PII, and PHI patterns",
    Pillar.TEST_QUALITY: "Pytest-aware test smells and project config checks",
    Pillar.DESIGN: "Project-level design rule",
}

_GROUP_ORDER = (
    "Size",
    "Complexity And Maintainability",
    "Dead Code And Waste",
    "Naming",
    "Documentation",
    "Security",
    "Sensitive Data",
    "Test Quality",
    "Design",
)


def render_rules_markdown(definitions: list[RuleDefinition] | None = None) -> str:
    """Render deterministic Markdown documentation for the built-in rule catalog.

    Args:
        definitions: Optional precomputed definitions. Defaults to the runtime
            default registry.

    Returns:
        Complete Markdown document content.
    """
    if definitions is None:
        definitions = [rule.definition() for rule in RuleRegistry.defaults().all()]
    definitions = sorted(definitions, key=lambda definition: definition.id)
    lines = [
        "# Rules",
        "",
        f"gruff-py `0.1` registers {len(definitions)} rules in `RuleRegistry.defaults()`.",
        "",
        "This file is generated from the first-party built-in rule catalog.",
        "Run `uv run python -m gruffpy.command.rule_docs --check docs/RULES.md` to verify it.",
        "",
        "## Pillar Summary",
        "",
        "| Pillar | Rule count | Notes |",
        "|---|---:|---|",
    ]
    counts = Counter(definition.pillar for definition in definitions)
    for pillar in _PILLAR_ORDER:
        count = counts.get(pillar, 0)
        if count:
            lines.append(f"| `{pillar.value}` | {count} | {_PILLAR_NOTES[pillar]} |")
    lines.extend(["", "## Rule IDs", ""])
    by_group = _definitions_by_group(definitions)
    for group in _GROUP_ORDER:
        items = by_group.get(group, [])
        if not items:
            continue
        lines.extend([f"### {group}", ""])
        for definition in items:
            suffix = " (default off)" if not definition.default_enabled else ""
            lines.append(f"- `{definition.id}`{suffix}")
        lines.append("")
    lines.extend(
        [
            "## Rule Details",
            "",
            "Each rule detail includes the runtime defaults, documentation metadata, "
            "and threshold contract where applicable.",
            "",
        ]
    )
    for definition in definitions:
        lines.extend(_rule_detail_lines(definition))
    lines.extend(_suppression_lines())
    lines.extend(_choosing_rules_lines())
    return "\n".join(lines).rstrip() + "\n"


def check_rules_markdown(path: Path) -> bool:
    """Return whether *path* matches generated rule docs.

    Args:
        path: Markdown file to compare against the freshly rendered output.

    Returns:
        True when the file is byte-identical to ``render_rules_markdown()``.
    """
    return path.read_text() == render_rules_markdown()


def write_rules_markdown(path: Path) -> None:
    """Write generated rule docs to *path*.

    Args:
        path: Destination markdown file; overwritten unconditionally.
    """
    path.write_text(render_rules_markdown())


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for docs generation/checking.

    Args:
        argv: Optional argv slice (defaults to ``sys.argv[1:]`` when ``None``).

    Returns:
        ``0`` on success or when docs are current; ``1`` if ``--check`` fails.
    """
    parser = argparse.ArgumentParser(description="Generate or check docs/RULES.md.")
    parser.add_argument("path", nargs="?", default="docs/RULES.md")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Fail if the docs are not current.")
    mode.add_argument("--write", action="store_true", help="Rewrite the docs file.")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if args.write:
        write_rules_markdown(path)
        return 0
    if args.check or not args.write:
        return 0 if check_rules_markdown(path) else 1
    return 0


def _definitions_by_group(definitions: list[RuleDefinition]) -> dict[str, list[RuleDefinition]]:
    groups: dict[str, list[RuleDefinition]] = {group: [] for group in _GROUP_ORDER}
    for definition in definitions:
        groups[_group_for(definition)].append(definition)
    return groups


def _group_for(definition: RuleDefinition) -> str:
    rule_prefix = definition.id.split(".", maxsplit=1)[0]
    match rule_prefix:
        case "size":
            return "Size"
        case "complexity":
            return "Complexity And Maintainability"
        case "dead-code" | "waste":
            return "Dead Code And Waste"
        case "naming":
            return "Naming"
        case "docs":
            return "Documentation"
        case "security":
            return "Security"
        case "sensitive-data":
            return "Sensitive Data"
        case "test-quality":
            return "Test Quality"
        case "design":
            return "Design"
    return definition.pillar.value.title()


def _rule_detail_lines(definition: RuleDefinition) -> list[str]:
    docs = documentation_for_rule(definition.id)
    lines = [
        f"### `{definition.id}`",
        "",
        f"- Name: {definition.name}",
        f"- Pillar: `{definition.pillar.value}`",
        f"- Tier: `{definition.tier.value}`",
        f"- Default severity: `{definition.default_severity.value}`",
        f"- Confidence: `{definition.confidence.value}`",
        f"- Default enabled: {'yes' if definition.default_enabled else 'no'}",
        f"- Rationale: {docs.rationale}",
        f"- Fix guidance: {docs.fix_guidance}",
        f"- Confidence rationale: {docs.confidence_rationale}",
    ]
    if _has_severity_thresholds(definition):
        lines.append(
            "- Config threshold: "
            f"`threshold` = `{definition.default_thresholds['error']!r}`, "
            "`severity` = `error`"
        )
    elif definition.default_thresholds:
        lines.append(f"- Named thresholds: {_inline_mapping(definition.default_thresholds)}")
    if definition.default_options:
        lines.append(f"- Options: {_inline_mapping(definition.default_options)}")
    if docs.threshold_metadata_keys:
        lines.append(f"- Threshold metadata: {_inline_list(docs.threshold_metadata_keys)}")
        lines.append(f"- Threshold direction: `{docs.threshold_direction}`")
    if docs.formula_provenance:
        lines.append(f"- Formula provenance: {docs.formula_provenance}")
    if docs.security_metadata:
        lines.append(f"- Security metadata: {_inline_mapping(docs.security_metadata)}")
    lines.extend(
        [
            f"- Bad example: {docs.bad_example}",
            f"- Good example: {docs.good_example}",
            "",
        ]
    )
    return lines


def _inline_mapping(mapping: dict[str, Any]) -> str:
    pairs = ", ".join(f"`{key}` = `{value!r}`" for key, value in sorted(mapping.items()))
    return pairs or "none"


def _has_severity_thresholds(definition: RuleDefinition) -> bool:
    return set(definition.default_thresholds) == {"warning", "error"}


def _inline_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"`{value}`" for value in values)


def _suppression_lines() -> list[str]:
    return [
        "## Suppressing Findings",
        "",
        "Use explicit gruff rule ids when a finding is a known false positive.",
        "Suppressions are applied after rule execution and before scoring/reporting.",
        "",
        "Suppress one rule on the same line:",
        "",
        "```python",
        "import os  # gruff: disable=waste.unused-import",
        "```",
        "",
        "Suppress one or more rules on the next physical line:",
        "",
        "```python",
        "# gruff: disable-next=security.dangerous-function-call,security.variable-import",
        "eval(payload)",
        "```",
        "",
        "Suppress one or more rules for the current file:",
        "",
        "```python",
        "# gruff: disable-file=size.file-length",
        "```",
        "",
        "`# noqa` remains rule-local compatibility behavior and is not a global gruff suppression.",
        "",
    ]


def _choosing_rules_lines() -> list[str]:
    return [
        "## Choosing Rules",
        "",
        "Run all defaults:",
        "",
        "```bash",
        "gruff-py analyse src/",
        "```",
        "",
        "Disable a rule:",
        "",
        "```yaml",
        "rules:",
        "  docs.missing-function-docstring:",
        "    enabled: false",
        "```",
        "",
        "Enable an opt-in rule:",
        "",
        "```yaml",
        "rules:",
        "  test-quality.testdox-readability:",
        "    enabled: true",
        "```",
        "",
        "Set one threshold for a metric rule:",
        "",
        "```yaml",
        "rules:",
        "  size.file-length:",
        "    threshold: 900",
        "    severity: error",
        "```",
        "",
        "Adjust a named threshold knob:",
        "",
        "```yaml",
        "rules:",
        "  test-quality.eager-test:",
        "    thresholds:",
        "      maxAssertions: 5",
        "```",
        "",
    ]


if __name__ == "__main__":
    raise SystemExit(main())
