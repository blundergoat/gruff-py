"""Tests for ``security.github-actions-secrets-in-pr``."""

from gruffpy.rule.security.github_actions_secrets_in_pr_rule import (
    GithubActionsSecretsInPrRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/pr.yml"


def test_pr_workflow_with_secret_fires():
    src = (
        "on: pull_request_target\njobs:\n  publish:\n    steps:\n      - run: npm publish\n"
        "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    )
    findings = GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["secret"] == "NPM_TOKEN"


def test_github_token_skipped():
    src = (
        "on: pull_request_target\njobs:\n  triage:\n    steps:\n      - run: gh pr view\n"
        "        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
    )
    assert GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_non_pr_workflow_with_secret_skipped():
    src = "on: push\njobs:\n  publish:\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    assert GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_plain_pull_request_workflow_is_not_reported():
    """A plain pull_request run from a fork receives no secrets, so its secret reference exposes nothing."""
    src = (
        "on:\n  pull_request:\n    branches: [main]\njobs:\n  publish:\n    steps:\n      - run: npm publish\n"
        "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    )
    assert GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_trigger_is_read_from_the_on_key_only():
    """An ``if:`` naming pull_request in an issue_comment workflow is not a trigger; flow and quoted forms are."""
    comment = "on: issue_comment\njobs:\n  x:\n    if: github.event.issue.pull_request\n    steps:\n      - run: echo ${{ secrets.NPM_TOKEN }}\n"
    flow = "on: [push, pull_request_target]\njobs:\n  x:\n    steps:\n      - run: echo ${{ secrets.NPM_TOKEN }}\n"
    quoted = '"on":\n  "pull_request_target":\n    types: [opened]\njobs:\n  x:\n    steps:\n      - run: echo ${{ secrets.NPM_TOKEN }}\n'
    rule = GithubActionsSecretsInPrRule()
    assert rule.analyse(make_text_unit(comment, _WF), default_ctx()) == []
    assert len(rule.analyse(make_text_unit(flow, _WF), default_ctx())) == 1
    assert len(rule.analyse(make_text_unit(quoted, _WF), default_ctx())) == 1
