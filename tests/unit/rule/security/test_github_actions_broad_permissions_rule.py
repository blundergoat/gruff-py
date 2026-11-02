"""Tests for ``security.github-actions-broad-permissions``."""

from gruffpy.rule.security.github_actions_broad_permissions_rule import (
    GithubActionsBroadPermissionsRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/ci.yml"


def test_write_all_fires():
    """Report one finding, on line 2, for ``permissions: write-all`` in a workflow."""
    src = "name: ci\npermissions: write-all\njobs: {}\n"
    findings = GithubActionsBroadPermissionsRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 2


def test_scoped_permissions_skipped():
    """Report nothing for scoped workflow permissions."""
    src = "permissions:\n  contents: read\n  pull-requests: write\n"
    assert GithubActionsBroadPermissionsRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_non_workflow_path_skipped():
    """Report nothing for ``write-all`` in a file outside the workflows folder."""
    src = "permissions: write-all\n"
    assert GithubActionsBroadPermissionsRule().analyse(make_text_unit(src, "k8s/role.yaml"), default_ctx()) == []
