"""Protect the generated rule catalog and current project-memory references.

These tests keep runtime definitions as the user's only numeric catalog source.
They also reject wrapped duplicate totals before stale prose reaches reviewers.
"""

import re
from pathlib import Path

import pytest

from gruffpy.command.rule_docs import check_rules_markdown, render_rules_markdown
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import VERSION

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_CURRENT_TRUTH_DOCS = (
    Path("README.md"),
    Path(".goat-flow/architecture.md"),
    Path(".goat-flow/code-map.md"),
    Path(".goat-flow/glossary.md"),
)
_LIVE_CATALOG_TOTAL_PATTERN = re.compile(
    r"\b\d+\s+rules\b.*?\b\d+\s+(?:active\s+)?pillars\b",
    flags=re.IGNORECASE | re.DOTALL,
)

_RENDERED_DOCS = render_rules_markdown()
# Runtime definitions model the exact catalog a CLI user receives by default.
_DEFAULT_DEFINITIONS = [rule.definition() for rule in RuleRegistry.defaults().all()]
# Stable rule ids let the test identify a missing or duplicated user-facing entry.
_DEFAULT_RULE_IDS = [definition.id for definition in _DEFAULT_DEFINITIONS]


def _live_catalog_total_in(relative_doc_path: Path) -> str | None:
    """Find a hand-maintained rule-and-pillar total in current project memory.

    Args:
        relative_doc_path: Non-empty repository path to one current-truth document.

    Returns:
        Matching total text, or ``None`` when users can only reach generated totals.
    """
    document_text = (_PROJECT_ROOT / relative_doc_path).read_text()
    normalized_document_text = " ".join(document_text.split())
    live_total_match = _LIVE_CATALOG_TOTAL_PATTERN.search(normalized_document_text)
    # A clean document gives reviewers no duplicate total to report.
    if live_total_match is None:
        return None
    return live_total_match.group(0)


def test_rendered_rule_docs_carry_the_catalog_structure() -> None:
    """Keep the generated catalog navigable for a user looking a rule up.

    Returns:
        None; a missing heading raises an assertion for the reviewer.
    """
    assert _RENDERED_DOCS.startswith("# Rules\n\n")
    assert "## Rule Details" in _RENDERED_DOCS
    assert "### `complexity.cyclomatic`" in _RENDERED_DOCS


def test_rendered_rule_docs_explain_how_a_rule_measures_and_misfires() -> None:
    """Keep the generated catalog useful for a user judging and fixing a finding.

    Returns:
        None; missing provenance or false-positive guidance raises an assertion.
    """
    threshold_metadata = "Threshold metadata: `measuredValue`, `threshold`, `thresholdDirection`, `thresholdType`"

    assert "Formula provenance: Radon-aligned decision-point counting." in _RENDERED_DOCS
    assert threshold_metadata in _RENDERED_DOCS
    assert "- Common false-positive shapes:" in _RENDERED_DOCS
    assert "A declarative builder dominated by one literal table" in _RENDERED_DOCS


def test_rendered_rule_docs_header_uses_runtime_totals() -> None:
    """Derive both catalog totals from definitions users receive at runtime.

    Returns:
        None; the exact generated header must match runtime rules and pillars.
    """
    # Distinct declared pillars avoid the known rule-id-prefix counting error.
    runtime_pillar_count = len({definition.pillar for definition in _DEFAULT_DEFINITIONS})
    expected_header = (
        f"gruff-py `{VERSION}` registers {len(_DEFAULT_DEFINITIONS)} rules across {runtime_pillar_count} pillars in `RuleRegistry.defaults()`."
    )

    assert _RENDERED_DOCS.splitlines()[2] == expected_header


def test_committed_rules_doc_is_current() -> None:
    """Keep the committed catalog identical to what runtime definitions render.

    Returns:
        None; stale generated documentation raises an assertion.
    """
    assert check_rules_markdown(_PROJECT_ROOT / "docs/rules.md")


def test_generated_docs_check_rejects_stale_header(tmp_path: Path) -> None:
    """Reject a generated catalog copy whose runtime rule total was changed.

    Args:
        tmp_path: Temporary location for the stale catalog a user might commit.

    Returns:
        None; the existing byte check must reject the deliberately stale file.
    """
    current_header = _RENDERED_DOCS.splitlines()[2]
    stale_header = current_header.replace(
        f"{len(_DEFAULT_DEFINITIONS)} rules",
        f"{len(_DEFAULT_DEFINITIONS) + 1} rules",
        1,
    )
    stale_catalog_path = tmp_path / "rules.md"
    stale_catalog_path.write_text(_RENDERED_DOCS.replace(current_header, stale_header, 1))

    assert not check_rules_markdown(stale_catalog_path)


@pytest.mark.parametrize(
    "relative_doc_path",
    _CURRENT_TRUTH_DOCS,
    ids=("readme", "architecture", "code-map", "glossary"),
)
def test_live_catalog_totals_are_generated_only(relative_doc_path: Path) -> None:
    """Keep current project memory linked to generated totals instead of copies.

    Args:
        relative_doc_path: Current-truth document checked for wrapped numeric totals.

    Returns:
        None; a duplicate total fails with the matching repository path.
    """
    live_catalog_total = _live_catalog_total_in(relative_doc_path)
    # A match means users could read a stale total instead of the generated catalog.
    assert live_catalog_total is None, f"{relative_doc_path} contains a live catalog total: {live_catalog_total!r}"


def test_live_catalog_totals_detector_rejects_wrapped_fixture(tmp_path: Path) -> None:
    """Recognize the wrapped stale-total shape that motivated the invariant.

    Args:
        tmp_path: Temporary current-memory location holding the stale example.

    Returns:
        None; the detector must reject a total split across physical lines.
    """
    stale_architecture_path = tmp_path / "architecture.md"
    stale_architecture_path.write_text("The runtime catalog has 125 rules across\n11 active pillars for reviewers.\n")

    wrapped_live_total = _live_catalog_total_in(stale_architecture_path)

    assert wrapped_live_total == "125 rules across 11 active pillars"


@pytest.mark.parametrize("rule_id", _DEFAULT_RULE_IDS, ids=lambda r: r)
def test_rendered_rule_docs_name_default_rule_once(rule_id: str) -> None:
    """Give users exactly one generated detail heading for each shipped rule.

    Args:
        rule_id: Non-empty id from the runtime catalog being checked.

    Returns:
        None; a missing or duplicate user-facing rule heading raises an assertion.
    """
    assert _RENDERED_DOCS.count(f"### `{rule_id}`") == 1
