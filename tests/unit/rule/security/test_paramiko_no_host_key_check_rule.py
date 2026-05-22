from gruffpy.rule.security.paramiko_no_host_key_check_rule import ParamikoNoHostKeyCheckRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_paramiko_autoaddpolicy_emits():
    src = (
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
    )
    findings = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["policy"] == "AutoAddPolicy"


def test_paramiko_warningpolicy_emits():
    src = (
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.WarningPolicy())\n"
    )
    findings = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["policy"] == "WarningPolicy"


def test_paramiko_rejectpolicy_skipped():
    src = (
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.RejectPolicy())\n"
    )
    assert ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx()) == []


def test_aliased_paramiko_import_emits():
    src = (
        "import paramiko as p\n"
        "client = p.SSHClient()\n"
        "client.set_missing_host_key_policy(p.AutoAddPolicy())\n"
    )
    findings = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_bare_import_autoaddpolicy_emits():
    src = (
        "from paramiko import SSHClient, AutoAddPolicy\n"
        "client = SSHClient()\n"
        "client.set_missing_host_key_policy(AutoAddPolicy())\n"
    )
    findings = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["policy"] == "AutoAddPolicy"


def test_bare_import_autoaddpolicy_with_alias_emits():
    src = (
        "from paramiko import AutoAddPolicy as YOLO\n"
        "client.set_missing_host_key_policy(YOLO())\n"
    )
    findings = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["policy"] == "AutoAddPolicy"


def test_non_paramiko_autoaddpolicy_skipped():
    """A class named AutoAddPolicy in an unrelated module must not fire."""
    src = "from other_lib import AutoAddPolicy\npolicy = AutoAddPolicy()\n"
    assert ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "import paramiko\npolicy = paramiko.AutoAddPolicy()\n"
    finding = ParamikoNoHostKeyCheckRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "ssh-host-key-policy"
    assert finding.metadata["sourceLabel"] == "ssh-handshake"
