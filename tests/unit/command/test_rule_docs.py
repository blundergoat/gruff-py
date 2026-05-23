from pathlib import Path

import pytest

from gruffpy.command.rule_docs import check_rules_markdown, render_rules_markdown
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_RENDERED_DOCS = render_rules_markdown()
_DEFAULT_RULE_IDS = [rule.definition().id for rule in RuleRegistry.defaults().all()]


def test_rendered_rule_docs_include_catalog_details() -> None:
    assert _RENDERED_DOCS.startswith("# Rules\n\n")
    assert "## Rule Details" in _RENDERED_DOCS
    assert "### `complexity.cyclomatic`" in _RENDERED_DOCS
    assert "Formula provenance: Radon-aligned decision-point counting." in _RENDERED_DOCS
    threshold_metadata = (
        "Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`"
    )
    assert threshold_metadata in _RENDERED_DOCS


def test_committed_rules_doc_is_current() -> None:
    assert check_rules_markdown(_PROJECT_ROOT / "docs/RULES.md")


@pytest.mark.parametrize("rule_id", _DEFAULT_RULE_IDS, ids=lambda r: r)
def test_rendered_rule_docs_name_default_rule_once(rule_id: str) -> None:
    assert _RENDERED_DOCS.count(f"### `{rule_id}`") == 1
