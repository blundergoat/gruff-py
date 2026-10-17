"""Build and verify the rule catalog shown to CLI users and reviewers.

The generator turns runtime definitions into the committed Markdown reference.
Contributors use write mode after catalog changes and check mode before release.
Readers then see rule, pillar, option, and remediation facts from one source.
"""

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from gruffpy.finding.pillar import Pillar
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import VERSION

_PILLAR_ORDER: tuple[Pillar, ...] = (
    Pillar.SIZE,
    Pillar.COMPLEXITY,
    Pillar.MAINTAINABILITY,
    Pillar.CORRECTNESS,
    Pillar.DEAD_CODE,
    Pillar.MODERNISATION,
    Pillar.NAMING,
    Pillar.DOCUMENTATION,
    Pillar.SECURITY,
    Pillar.SENSITIVE_DATA,
    Pillar.TEST_QUALITY,
    Pillar.DESIGN,
)

_PILLAR_NOTES = {
    Pillar.SIZE: "File, class, function, parameter, method, and attribute size",
    Pillar.COMPLEXITY: "Cyclomatic, cognitive, and nesting",
    Pillar.MAINTAINABILITY: "Reserved after the maintainability-index rule retired",
    Pillar.CORRECTNESS: "Mechanically detectable runtime-defect shapes",
    Pillar.DEAD_CODE: "Unused and waste-oriented rules",
    Pillar.MODERNISATION: "Python syntax and library modernisation opportunities",
    Pillar.NAMING: "Intent-layer names; PEP 8 case style stays with ruff",
    Pillar.DOCUMENTATION: ("Docstring presence and quality, stale docs, TODO density, README presence"),
    Pillar.SECURITY: "Heuristic AST-level dangerous patterns",
    Pillar.SENSITIVE_DATA: "Secret, key, PII, and PHI patterns",
    Pillar.TEST_QUALITY: "Pytest-aware test smells and project config checks",
    Pillar.DESIGN: "Project-level abstraction and runtime import-path checks",
}

_GROUP_ORDER = (
    "Size",
    "Complexity And Maintainability",
    "Correctness",
    "Dead Code And Waste",
    "Modernisation",
    "Naming",
    "Documentation",
    "Security",
    "Sensitive Data",
    "Test Quality",
    "Design",
)

_M02_DEFAULT_OFF_REASONS = {
    "security.weak-crypto": (
        "Opt-in after M02's bounded repair: fewer than ten findings remain in the explicitly enabled corpus, "
        "below the minimum needed to assess the 0.80 security precision floor. Explicit enablement retains the repair."
    ),
    "security.hardcoded-framework-secret-key": (
        "Opt-in under M02: only one current corpus finding remains after the shared test-path exclusion, "
        "below the minimum of ten needed to assess the 0.80 security precision floor. Explicit enablement retains the detector."
    ),
    "security.insecure-temp-file": (
        "Opt-in under M02: no current corpus findings remain after the shared test-path exclusion, "
        "below the minimum of ten needed to assess the 0.80 security precision floor. Explicit enablement retains the detector."
    ),
    "security.silent-except": (
        "Opt-in after M02's bounded repair: 21 of 29 judged findings were worth acting on, below the 0.80 security floor. "
        "The enabled repair preserved every judged-right finding; default scans omit them until the rule is explicitly enabled."
    ),
    "docs.missing-return-doc": (
        "Retained for bounded repair under M02's return-documentation exception: four right of twenty judged findings did not establish "
        "the 0.60 floor. The repair accepts recognized result prose; fresh blind validation is pending."
    ),
    "complexity.cyclomatic": (
        "Remains opt-in after M14's bounded repair: 26 of 50 judged upper-band findings were worth acting on, below its 0.60 precision floor."
    ),
    "security.dangerous-function-call": (
        "Opt-in after M02's blind provenance review remained insufficient: 10 right of 15 judged, with 10 unresolved labels."
    ),
    "security.header-injection": (
        "Opt-in after M02's blind provenance review remained insufficient: neither of two judged findings was right, "
        "and one label remained unresolved."
    ),
    "security.unsafe-yaml-load": (
        "Opt-in after M02's blind provenance review remained insufficient: two right of three judged, with one unresolved label."
    ),
    "security.variable-import": (
        "Opt-in after M02's blind provenance review remained insufficient: three right of eleven judged, with eight unresolved labels."
    ),
    "security.xxe": (
        "Opt-in after M02: only three default findings, two right and one unresolved, leave too little evidence for the precision floor."
    ),
    "sensitive-data.database-url-password": (
        "Opt-in after M02: none of seven judged findings was right, but only eight default findings were available, too few for deletion."
    ),
    "test-quality.no-assertions": (
        "Remains opt-in under M02's accepted table: seven right of 36 judged findings do not establish its 0.70 precision floor."
    ),
    "test-quality.sut-not-called": (
        "Remains opt-in under M02's accepted table: nine right of 28 judged findings do not establish its 0.70 precision floor."
    ),
}


def render_rules_markdown(definitions: list[RuleDefinition] | None = None) -> str:
    """Render deterministic Markdown documentation for the built-in rule catalog.

    Args:
        definitions: Optional precomputed definitions. ``None`` uses the rules
            shipped to CLI users; an empty list renders an empty catalog shell.

    Returns:
        Complete Markdown document content; it is never empty.
    """
    # A contributor normally omits definitions to document the rules users receive.
    if definitions is None:
        definitions = [rule.definition() for rule in RuleRegistry.defaults().all()]
    definitions = sorted(definitions, key=lambda definition: definition.id)
    # Declared pillars keep the displayed total aligned with user-visible findings.
    rule_counts_by_pillar = Counter(definition.pillar for definition in definitions)
    lines = [
        "# Rules",
        "",
        (f"gruff-py `{VERSION}` registers {len(definitions)} rules across {len(rule_counts_by_pillar)} pillars in `RuleRegistry.defaults()`."),
        "",
        "This file is generated from the first-party built-in rule catalog.",
        "Run `uv run python -m gruffpy.command.rule_docs --check docs/rules.md` to verify it.",
        "",
        "## Pillar Summary",
        "",
        "| Pillar | Rule count | Notes |",
        "|---|---:|---|",
    ]
    # Readers see active pillars in a stable order across generated releases.
    for pillar in _PILLAR_ORDER:
        registered_rule_count = rule_counts_by_pillar.get(pillar, 0)
        # An empty pillar is reserved and gives users no rule row to configure.
        if registered_rule_count:
            lines.append(f"| `{pillar.value}` | {registered_rule_count} | {_PILLAR_NOTES[pillar]} |")
    lines.extend(["", "## Rule IDs", ""])
    by_group = _definitions_by_group(definitions)
    # Readers browse familiar feature sections before opening individual rule details.
    for group in _GROUP_ORDER:
        items = by_group.get(group, [])
        # A section with no shipped rules would only add an empty heading for users.
        if not items:
            continue
        lines.extend([f"### {group}", ""])
        # Each catalog item links the user's rule id to its default-enabled posture.
        for definition in items:
            suffix = " (default off)" if not definition.default_enabled else ""
            lines.append(f"- `{definition.id}`{suffix}")
        lines.append("")
    lines.extend(
        [
            "## Rule Details",
            "",
            "Each rule detail includes the runtime defaults, documentation metadata, and threshold contract where applicable.",
            "",
        ]
    )
    # The detail section gives users the settings and remediation for every listed id.
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

    Returns:
        None; an empty or stale destination becomes the complete current catalog.
    """
    path.write_text(render_rules_markdown())


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for docs generation/checking.

    Args:
        argv: Optional argv slice (defaults to ``sys.argv[1:]`` when ``None``).

    Returns:
        ``0`` on success or when docs are current; ``1`` if ``--check`` fails.
    """
    parser = argparse.ArgumentParser(description="Generate or check docs/rules.md.")
    parser.add_argument("path", nargs="?", default="docs/rules.md")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Fail if the docs are not current.")
    mode.add_argument("--write", action="store_true", help="Rewrite the docs file.")
    args = parser.parse_args(argv)
    path = Path(args.path)
    # A contributor chooses write mode after changing the rules shipped to users.
    if args.write:
        write_rules_markdown(path)
        return 0
    # Release checks compare bytes so stale user documentation fails without a rewrite.
    if args.check or not args.write:
        return 0 if check_rules_markdown(path) else 1
    return 0


def _definitions_by_group(definitions: list[RuleDefinition]) -> dict[str, list[RuleDefinition]]:
    """Group runtime rules into the sections users browse in generated docs.

    Args:
        definitions: Runtime definitions to display; an empty list leaves every
            user-facing section empty.

    Returns:
        Every ordered section mapped to its rules, including empty sections.
    """
    # Keeping empty buckets preserves stable section order while rules move over time.
    groups: dict[str, list[RuleDefinition]] = {group: [] for group in _GROUP_ORDER}
    # Each shipped rule appears in exactly one section a reader can scan.
    for definition in definitions:
        groups[_group_for(definition)].append(definition)
    return groups


def _group_for(definition: RuleDefinition) -> str:
    """Choose the generated-doc section where a user finds one rule.

    Args:
        definition: One non-empty runtime rule definition.

    Returns:
        Stable user-facing section heading for the rule.
    """
    rule_prefix = definition.id.split(".", maxsplit=1)[0]
    match rule_prefix:
        case "size":
            return "Size"
        case "complexity":
            return "Complexity And Maintainability"
        case "correctness":
            return "Correctness"
        case "dead-code" | "waste":
            return "Dead Code And Waste"
        case "modernisation":
            return "Modernisation"
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
    """Render the settings and guidance a user needs to act on one rule.

    Args:
        definition: One non-empty runtime rule definition to explain.

    Returns:
        Non-empty Markdown lines for the rule's catalog detail section.
    """
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
    if not definition.default_enabled and definition.id in _M02_DEFAULT_OFF_REASONS:
        lines.append(f"- Default-off reason: {_M02_DEFAULT_OFF_REASONS[definition.id]}")
    # Metric rules show the threshold a user can tune for finding severity.
    if _has_severity_thresholds(definition):
        lines.append(f"- Config threshold: `threshold` = `{definition.default_threshold!r}`, `severity` = `{definition.default_severity.value}`")
    # Named thresholds expose several user-tunable limits instead of one metric cutoff.
    elif definition.default_thresholds:
        lines.append(f"- Named thresholds: {_inline_mapping(definition.default_thresholds)}")
    # Options explain non-threshold behavior users can configure for this rule.
    if definition.default_options:
        lines.append(f"- Options: {_inline_mapping(definition.default_options)}")
    # Metadata keys help report consumers interpret a threshold-based finding.
    if docs.threshold_metadata_keys:
        lines.append(f"- Threshold metadata: {_inline_list(docs.threshold_metadata_keys)}")
        lines.append(f"- Threshold direction: `{docs.threshold_direction}`")
    # Formula provenance lets reviewers trace how a measured value was calculated.
    if docs.formula_provenance:
        lines.append(f"- Formula provenance: {docs.formula_provenance}")
    # Security metadata gives users the sink/source context attached to a finding.
    if docs.security_metadata:
        lines.append(f"- Security metadata: {_inline_mapping(docs.security_metadata)}")
    if docs.false_positive_shapes:
        lines.append("- Common false-positive shapes:")
        for false_positive_shape in docs.false_positive_shapes:
            lines.append(f"  - {false_positive_shape.shape}")
            lines.append(f"    Mitigation: {false_positive_shape.mitigation}")
    lines.extend(
        [
            f"- Bad example: {docs.bad_example}",
            f"- Good example: {docs.good_example}",
            "",
        ]
    )
    return lines


def _inline_mapping(mapping: dict[str, Any]) -> str:
    """Format option values for a compact user-facing catalog line.

    Args:
        mapping: Option names and values; an empty mapping means no settings.

    Returns:
        Sorted inline settings, or ``none`` when users have nothing to configure.
    """
    # Sorted settings keep generated diffs predictable for reviewers.
    pairs = ", ".join(f"`{key}` = `{value!r}`" for key, value in sorted(mapping.items()))
    # An empty mapping is rendered explicitly instead of leaving a blank catalog value.
    return pairs or "none"


def _has_severity_thresholds(definition: RuleDefinition) -> bool:
    """Report whether a user can tune one severity threshold for this rule.

    Args:
        definition: Runtime rule definition whose threshold contract is displayed.

    Returns:
        ``False`` when no single threshold is available to the user.
    """
    return definition.default_threshold is not None


def _inline_list(values: tuple[str, ...]) -> str:
    """Format metadata names for one readable generated-doc line.

    Args:
        values: Metadata names to show; an empty tuple produces empty text.

    Returns:
        Comma-separated inline-code names, or empty text for no names.
    """
    # Each metadata name is styled as code so report consumers can copy it exactly.
    return ", ".join(f"`{value}`" for value in values)


def _suppression_lines() -> list[str]:
    """Render examples users follow when suppressing reviewed findings.

    Returns:
        Non-empty Markdown lines covering same-line, next-line, and file scope.
    """
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
    """Render examples users follow when selecting or configuring rules.

    Returns:
        Non-empty Markdown lines for default scans, disabling, and thresholds.
    """
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
        "  test-quality.excessive-mocking:",
        "    thresholds:",
        "      maxMocks: 4",
        "```",
        "",
    ]


# Direct module use lets a contributor write or check the catalog from the terminal.
if __name__ == "__main__":
    raise SystemExit(main())
