"""Tests for ``security.github-actions-secrets-in-pr``."""

from gruffpy.rule.security.github_actions_secrets_in_pr_rule import (
    GithubActionsSecretsInPrRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/pr.yml"


def test_pr_workflow_with_secret_fires():
    src = (
        "on: pull_request\njobs:\n  publish:\n    steps:\n      - run: npm publish\n"
        "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    )
    findings = GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["secret"] == "NPM_TOKEN"


def test_github_token_skipped():
    src = (
        "on: pull_request\njobs:\n  triage:\n    steps:\n      - run: gh pr view\n"
        "        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
    )
    assert GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_non_pr_workflow_with_secret_skipped():
    src = (
        "on: push\njobs:\n  publish:\n    steps:\n      - run: npm publish\n"
        "        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
    )
    assert GithubActionsSecretsInPrRule().analyse(make_text_unit(src, _WF), default_ctx()) == []
