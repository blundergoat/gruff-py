from pathlib import Path

import pytest

from gruffpy.config.exceptions import ConfigError
from gruffpy.config.yaml_loader import load_gruff_py_yaml


def test_loads_basic_yaml(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(
        "paths:\n"
        "  ignore:\n"
        "    - build/\n"
        "    - .venv/\n"
        "rules:\n"
        "  size.file-length:\n"
        "    thresholds:\n"
        "      warning: 500\n"
        "      error: 1000\n"
    )
    data = load_gruff_py_yaml(path)
    assert data["paths"]["ignore"] == ["build/", ".venv/"]
    assert data["rules"]["size.file-length"]["thresholds"]["warning"] == 500


def test_empty_file_returns_empty_dict(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("")
    assert load_gruff_py_yaml(path) == {}


def test_comments_only_returns_empty_dict(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("# just comments\n# more comments\n")
    assert load_gruff_py_yaml(path) == {}


def test_list_at_root_raises_config_error(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("- foo\n- bar\n")
    with pytest.raises(ConfigError, match="top-level must be a mapping"):
        load_gruff_py_yaml(path)


def test_invalid_yaml_raises_config_error(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("paths:\n  ignore:\n  -  - nested-bad: x: y\n")
    with pytest.raises(ConfigError, match="Failed to parse YAML"):
        load_gruff_py_yaml(path)


def test_missing_file_raises_config_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="Failed to read config file"):
        load_gruff_py_yaml(tmp_path / "does-not-exist.yaml")


def test_dotted_rule_keys_preserved(tmp_path: Path):
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(
        "rules:\n"
        "  size.file-length:\n"
        "    enabled: true\n"
        "  complexity.cyclomatic:\n"
        "    thresholds:\n"
        "      warning: 8\n"
    )
    data = load_gruff_py_yaml(path)
    assert "size.file-length" in data["rules"]
    assert "complexity.cyclomatic" in data["rules"]
    assert data["rules"]["complexity.cyclomatic"]["thresholds"]["warning"] == 8
