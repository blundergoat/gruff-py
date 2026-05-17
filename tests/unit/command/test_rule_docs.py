from pathlib import Path

from gruffpy.command.rule_docs import check_rules_markdown, render_rules_markdown
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_rendered_rule_docs_include_catalog_details() -> None:
    content = render_rules_markdown()

    assert content.startswith("# Rules\n\n")
    assert "## Rule Details" in content
    assert "### `complexity.cyclomatic`" in content
    assert "Formula provenance: Radon-aligned decision-point counting." in content
    threshold_metadata = (
        "Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`"
    )
    assert threshold_metadata in content


def test_committed_rules_doc_is_current() -> None:
    assert check_rules_markdown(_PROJECT_ROOT / "docs/RULES.md")


def test_rendered_rule_docs_names_every_default_rule_once() -> None:
    content = render_rules_markdown()
    for rule in RuleRegistry.defaults().all():
        rule_id = rule.definition().id
        assert content.count(f"### `{rule_id}`") == 1
