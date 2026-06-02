"""Tests for ``security.github-actions-broad-permissions``."""

from gruffpy.rule.security.github_actions_broad_permissions_rule import (
    GithubActionsBroadPermissionsRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/ci.yml"


def test_write_all_fires():
    src = "name: ci\npermissions: write-all\njobs: {}\n"
    findings = GithubActionsBroadPermissionsRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 2


def test_scoped_permissions_skipped():
    src = "permissions:\n  contents: read\n  pull-requests: write\n"
    assert (
        GithubActionsBroadPermissionsRule().analyse(make_text_unit(src, _WF), default_ctx()) == []
    )


def test_non_workflow_path_skipped():
    src = "permissions: write-all\n"
    assert (
        GithubActionsBroadPermissionsRule().analyse(
            make_text_unit(src, "k8s/role.yaml"), default_ctx()
        )
        == []
    )
