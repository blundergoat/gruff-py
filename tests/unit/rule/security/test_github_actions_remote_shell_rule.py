"""Tests for ``security.github-actions-remote-shell``."""

from gruffpy.rule.security.github_actions_remote_shell_rule import (
    GithubActionsRemoteShellRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_text_unit

_WF = ".github/workflows/ci.yml"


def test_curl_pipe_bash_fires():
    src = "    steps:\n      - run: curl -fsSL https://example.com/install.sh | bash\n"
    findings = GithubActionsRemoteShellRule().analyse(make_text_unit(src, _WF), default_ctx())
    assert len(findings) == 1
    assert findings[0].line == 2


def test_wget_pipe_sudo_sh_fires():
    src = "      - run: wget -qO- https://example.com/i.sh | sudo sh\n"
    assert len(GithubActionsRemoteShellRule().analyse(make_text_unit(src, _WF), default_ctx())) == 1


def test_download_to_file_then_verify_skipped():
    src = "      - run: curl -fsSL https://example.com/i.sh -o i.sh && sha256sum -c i.sha256\n"
    assert GithubActionsRemoteShellRule().analyse(make_text_unit(src, _WF), default_ctx()) == []


def test_non_workflow_path_skipped():
    src = "      - run: curl https://example.com/i.sh | bash\n"
    assert (
        GithubActionsRemoteShellRule().analyse(
            make_text_unit(src, "scripts/setup.yml"), default_ctx()
        )
        == []
    )
