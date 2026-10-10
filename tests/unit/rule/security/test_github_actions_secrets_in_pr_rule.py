"""Tests for ``security.github-actions-secrets-in-pr``."""

import pytest

from gruffpy.rule.security.github_actions_secrets_in_pr_rule import (
    GithubActionsSecretsInPrRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/pr.yml"


_OWN_WORKFLOW_EVENT_GUARD_CASES = (
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name != 'pull_request_target'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    if: ${{ !(github.event_name == 'pull_request_target') }}\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    if: (github.event_name == 'push' || github.event_name == 'issues')\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues' && inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    if: inputs.enabled && github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'PULL_REQUEST_TARGET'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'pull_request_target'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name != 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues' || inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: ${{ github.event_name == 'issues' }} trailing\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues' trailing\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues' &&\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    if: github.event_name == 'issues' && contains(inputs.x, 'x')\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 0\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: !github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n    if: github.event_name == 'issues'\n",
        0,
    ),
    (
        "'jobs':\n  'build':\n    'steps':\n      - 'run': echo ${{ secrets.DEPLOY_TOKEN }}\n        'if': github.event_name == 'issues'\n",
        0,
    ),
    (
        "jobs:\n  build:\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        0,
    ),
    (
        "jobs:\n  build:\n    steps:\n      - run: |\n          if: github.event_name == 'issues'\n          echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    steps:\n      - run: |\n          echo ${{ secrets.DEPLOY_TOKEN }}\n        if: github.event_name == 'issues'\n",
        0,
    ),
    (
        "env:\n  TOKEN: ${{ secrets.DEPLOY_TOKEN }}\njobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ready\n",
        1,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    env:\n"
        "      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "    steps:\n"
        "      - if: github.event_name == 'issues'\n"
        "        run: echo ready\n",
        1,
    ),
    (
        "jobs:\n"
        "  safe:\n"
        "    if: github.event_name == 'issues'\n"
        "    steps:\n"
        "      - run: echo ready\n"
        "  build:\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - if: github.event_name == 'issues'\n"
        "        run: echo ready\n"
        "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n        with:\n          if: github.event_name == 'issues'\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues'\n    if: inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    if: github.event_name == 'issues'\n"
        "    steps:\n"
        "      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n"
        "  build:\n"
        "    steps:\n"
        "      - run: echo ready\n",
        1,
    ),
    (
        "jobs:\n"
        "  build:\n"
        "    if: github.event_name == 'issues'\n"
        "    env: &shared\n"
        "      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "    steps:\n"
        "      - run: echo ready\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues'\n    <<: *shared\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n",
        1,
    ),
    (
        "jobs: {build: {if: \"github.event_name == 'issues'\", env: {TOKEN: ${{ secrets.DEPLOY_TOKEN }}}}}\n",
        1,
    ),
    (
        "jobs:\n  build:\n    if: github.event_name == 'issues'\n    env:\n      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n    steps:\n      - *shared\n",
        1,
    ),
)
_OWN_WORKFLOW_EVENT_GUARD_IDS = (
    "expression github.event_name == 'issues'",
    "expression github.event_name != 'pull_request_target'",
    "expression ${{ !(github.event_name == 'pull_request_target') }}",
    "expression (github.event_name == 'push' || github.event_name == 'issues')",
    "expression github.event_name == 'issues' && inputs.enabled",
    "expression inputs.enabled && github.event_name == 'issues'",
    "expression github.event_name == 'PULL_REQUEST_TARGET'",
    "expression github.event_name == 'pull_request_target'",
    "expression github.event_name != 'issues'",
    "expression inputs.enabled",
    "expression github.event_name == 'issues' || inputs.enabled",
    "expression ${{ github.event_name == 'issues' }} trailing",
    "expression github.event_name == 'issues' trailing",
    "expression github.event_name == 'issues' &&",
    "expression github.event_name == 'issues' && contains(inputs.x, 'x')",
    "expression github.event_name == 0",
    "expression !github.event_name == 'issues'",
    "ownership 1",
    "ownership 2",
    "ownership 3",
    "ownership 4",
    "ownership 5",
    "ownership 6",
    "ownership 7",
    "ownership 8",
    "ownership 9",
    "ownership 10",
    "ownership 11",
    "ownership 12",
    "ownership 13",
    "ownership 14",
    "ownership 15",
    "scalar list alias",
)


@pytest.mark.parametrize(("body", "expected"), _OWN_WORKFLOW_EVENT_GUARD_CASES, ids=_OWN_WORKFLOW_EVENT_GUARD_IDS)
def test_own_workflow_event_guard(body: str, expected: int) -> None:
    """Only own PR-unreachable guards may suppress a source reference.

    Args:
        body: Workflow text after the ``pull_request_target`` trigger, holding the guard under test.
        expected: Secret findings the rule must report; zero means the guard proves the job unreachable from a PR.
    """
    source = "on:\n  pull_request_target:\n" + body
    findings = GithubActionsSecretsInPrRule().analyse(make_text_unit(source, _WF), default_ctx())
    assert len(findings) == expected


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
