"""Tests for ``security.github-actions-unpinned-action``."""

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.security.github_actions_unpinned_action_rule import (
    GithubActionsUnpinnedActionRule,
)
from gruffpy.source.source_file import SourceFile

_WORKFLOW_PATH = ".github/workflows/ci.yml"


def _unit(source: str, display_path: str = _WORKFLOW_PATH) -> AnalysisUnit:
    """Build a text-typed workflow ``AnalysisUnit`` (``tree=None``)."""
    file = SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="text")
    return AnalysisUnit(file=file, source=source, tree=None)


def _ctx() -> RuleContext:
    """Build a default ``RuleContext`` seeded from the built-in registry."""
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    return RuleContext(project_root="/tmp/no-such-root", config=config)


def test_tag_pinned_third_party_action_fires():
    src = "jobs:\n  build:\n    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    findings = GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["action"] == "pypa/gh-action-pypi-publish"
    assert findings[0].metadata["ref"] == "release/v1"


def test_branch_pinned_action_fires():
    src = "      - uses: some-org/deploy@main\n"
    assert len(GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx())) == 1


def test_sha_pinned_action_skipped():
    sha = "a1b2c3d4e5f6" + "0" * 28  # 40-char hex
    src = f"      - uses: some-org/deploy@{sha}\n"
    assert GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx()) == []


def test_first_party_actions_org_skipped():
    src = "      - uses: actions/checkout@v4\n"
    assert GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx()) == []


def test_local_action_skipped():
    src = "      - uses: ./.github/actions/setup\n"
    assert GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx()) == []


def test_docker_reference_skipped():
    src = "      - uses: docker://ghcr.io/org/image:1.2.3\n"
    assert GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx()) == []


def test_reusable_workflow_unpinned_fires():
    src = "    uses: org/repo/.github/workflows/release.yml@v2\n"
    findings = GithubActionsUnpinnedActionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["ref"] == "v2"


def test_non_workflow_path_skipped():
    # Identical content outside .github/workflows/ must not be scanned.
    src = "      - uses: some-org/deploy@main\n"
    assert GithubActionsUnpinnedActionRule().analyse(_unit(src, "config/other.yml"), _ctx()) == []


def test_fires_via_registry_text_seam():
    # Proves the SourceTextRule dispatch routes workflow text to the rule.
    src = "      - uses: some-org/deploy@main\n"
    findings = RuleRegistry.defaults().analyse([_unit(src)], _ctx())
    assert "security.github-actions-unpinned-action" in {f.rule_id for f in findings}
