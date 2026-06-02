"""Tests for ``security.github-actions-pull-request-target``."""

from gruffpy.rule.security.github_actions_pull_request_target_rule import (
    GithubActionsPullRequestTargetRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/pr.yml"


def test_target_with_head_checkout_fires():
    src = (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    findings = GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 2


def test_target_without_head_checkout_skipped():
    src = (
        "on:\n  pull_request_target:\n    types: [labeled]\n"
        "jobs:\n  x:\n    steps:\n      - run: echo hi\n"
    )
    assert (
        GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx()) == []
    )


def test_plain_pull_request_with_head_checkout_skipped():
    # `pull_request` (not `_target`) does not grant the privileged token, so even
    # a head checkout is the supported, safe pattern - this rule must stay quiet.
    src = (
        "on: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert (
        GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx()) == []
    )
