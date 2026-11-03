from gruffpy.rule.security.shell_injection_rule import ShellInjectionRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_subprocess_run_shell_true_with_dynamic_command_emits():
    """Report one finding for ``subprocess.run`` with ``shell=True`` on an f-string command."""
    src = "import subprocess\nsubprocess.run(f'rm {target}', shell=True)\n"
    findings = ShellInjectionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_subprocess_run_shell_false_skipped():
    """Report nothing for ``subprocess.run`` with an argument list and no shell."""
    src = "import subprocess\nsubprocess.run(['ls', target])\n"
    assert ShellInjectionRule().analyse(make_unit(src), default_ctx()) == []


def test_subprocess_run_shell_true_static_skipped():
    """Report nothing for ``subprocess.run`` with ``shell=True`` on a literal command."""
    src = "import subprocess\nsubprocess.run('ls -la', shell=True)\n"
    assert ShellInjectionRule().analyse(make_unit(src), default_ctx()) == []


def test_os_system_dynamic_emits():
    """Report one finding for ``os.system`` on an f-string command."""
    src = "import os\nos.system(f'rm {target}')\n"
    findings = ShellInjectionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_os_system_static_skipped():
    """Report nothing for ``os.system`` on a literal command."""
    src = "import os\nos.system('ls')\n"
    assert ShellInjectionRule().analyse(make_unit(src), default_ctx()) == []
