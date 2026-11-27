"""Tests for ``security.github-actions-pull-request-target``."""

from gruffpy.rule.security.github_actions_pull_request_target_rule import (
    GithubActionsPullRequestTargetRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/pr.yml"


def test_target_with_head_checkout_fires():
    """Report one finding, on the trigger line, for a ``pull_request_target`` workflow that checks out the pull request head.

    Returns:
        None after the assertions pass.
    """
    src = (
        "on:\n  pull_request_target:\n    types: [opened]\n"
        "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    findings = GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 2


def test_target_without_head_checkout_skipped():
    """Report nothing for a ``pull_request_target`` workflow that does not check out the head.

    Returns:
        None after the assertion passes.
    """
    src = "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  x:\n    steps:\n      - run: echo hi\n"
    assert GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_plain_pull_request_with_head_checkout_skipped():
    """Report nothing for a plain ``pull_request`` workflow that checks out the head.

    Returns:
        None. Checks that a plain pull_request workflow with a head checkout produces no findings from this rule.
    """
    # Keep the PR-head checkout from the positive case to isolate the change of trigger.
    # The rule requires the pull_request_target trigger for this finding.
    src = (
        "on: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert GithubActionsPullRequestTargetRule().analyse(make_text_unit(src, _WF), default_ctx()) == []
