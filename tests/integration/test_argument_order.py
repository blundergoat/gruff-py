"""Pin the argument-order clause FAMILY-CONTRACT.md section 7 ratifies on 2026-09-06.

Every operand-accepting command must produce the same output and the same exit
code whether its flags are written before or after the path. The defect the
clause exists to prevent is real and was shipped: gruff-go silently discarded
flags placed after a path, so ``analyse . --fail-on=error`` ran at the default
threshold and a CI gate nobody had disabled stopped gating.

Reach for this module when adding a command that takes paths, or when changing
how the console parses arguments.
"""

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

# The one field two runs of the same command are allowed to differ on.
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?")

# Every operand-accepting command, with the flags whose placement is under test.
_OPERAND_COMMANDS = (
    ("analyse", ("--no-config", "--fail-on", "none", "--format", "json")),
    ("summary", ("--no-config", "--format", "json")),
    ("hook", ("--no-config", "--format", "json")),
    ("check-ignore", ("--no-config", "--format", "json")),
)


@pytest.fixture(name="probe_project")
def fixture_probe_project(tmp_path: Path) -> Path:
    """Build a one-file project the ordering comparison can scan.

    Args:
        tmp_path: pytest's per-test temporary directory.

    Returns:
        The project root, carrying one module and a README so the comparison is
        about ordering rather than about which incidental findings appeared.
    """
    (tmp_path / "probe.py").write_text('"""Probe module."""\n\n\ndef probe(rx: int) -> int:\n    return rx + rx\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("Argument-order fixture.\n", encoding="utf-8")
    return tmp_path


def _without_timestamps(output: str) -> str:
    """Replace every generated timestamp with a fixed marker, so two runs compare on their substance."""
    return _TIMESTAMP.sub("<timestamp>", output)


@pytest.mark.parametrize(("command", "flags"), _OPERAND_COMMANDS, ids=[name for name, _ in _OPERAND_COMMANDS])
def test_flags_after_the_path_change_nothing(command: str, flags: tuple[str, ...], probe_project: Path) -> None:
    """Moving a command's flags after its path changes neither its output nor its exit code.

    Args:
        command: The operand-accepting command under test.
        flags: The flags whose placement is being moved.
        probe_project: The one-file project both runs scan.
    """
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=probe_project.parent):
        before = runner.invoke(main, [command, *flags, str(probe_project / "probe.py")])
        after = runner.invoke(main, [command, str(probe_project / "probe.py"), *flags])

    assert before.exit_code == after.exit_code, f"{command} exits differently when its flags follow the path"
    assert _without_timestamps(before.output) == _without_timestamps(after.output), f"{command} prints differently when its flags follow the path"


def test_double_dash_ends_flag_parsing(probe_project: Path) -> None:
    """A leading-dash operand after ``--`` is reachable as a path rather than read as a flag.

    Args:
        probe_project: The project the dashed file is added to.
    """
    dashed = probe_project / "-dashed.py"
    dashed.write_text('"""Dashed module."""\n\n\ndef dashed(rx: int) -> int:\n    return rx + rx\n', encoding="utf-8")

    result = CliRunner().invoke(main, ["analyse", "--no-config", "--fail-on", "none", "--format", "json", "--", str(dashed)])

    assert result.exit_code == 0, result.output
    assert "-dashed.py" in result.output


def test_a_command_without_operands_rejects_a_stray_one() -> None:
    """A command taking no operands rejects one rather than discarding it silently."""
    result = CliRunner().invoke(main, ["init", "stray-operand"])

    # Exit 2 is the family's usage exit; 1 would read to a CI gate as findings.
    assert result.exit_code == 2, result.output
