"""Size and complexity rules measure only Python source (FAMILY-CONTRACT.md section 12, "Size and complexity findings in two bands")."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from gruffpy.cli import main


def test_long_data_files_report_no_size_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep size and complexity findings off long JSON, YAML and TOML files while a 1,600-line Python module still reports one.

    Args:
        tmp_path: Project root whose ``src`` folder holds the long JSON, YAML and TOML data files and the 1,600-line module.
        monkeypatch: Changes into the project so the relative ``src`` operand resolves.
    """
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "data.json").write_text("[\n" + "".join(f'  {{"key": {i}}},\n' for i in range(1600)) + "  {}\n]\n")
    (src / "data.yaml").write_text("".join(f"key{i}: {i}\n" for i in range(1600)))
    (src / "data.toml").write_text("".join(f"key{i} = {i}\n" for i in range(1600)))
    (src / "long.py").write_text("".join(f"x{i} = {i}\n" for i in range(1600)))

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "--fail-on", "none", "--no-config", "src"])

    assert result.exit_code == 0, result.output
    size_files = {finding["file"] for finding in json.loads(result.output)["findings"] if finding["ruleId"].startswith(("size.", "complexity."))}
    assert size_files == {"src/long.py"}
