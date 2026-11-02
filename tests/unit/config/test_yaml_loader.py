from pathlib import Path

import pytest

from gruffpy.config.exceptions import ConfigError
from gruffpy.config.yaml_loader import load_gruff_py_yaml


def test_loads_basic_yaml(tmp_path: Path):
    """Read the ignore paths and a nested warning tier from a YAML config.

    Args:
        tmp_path: Holds a config with ignore paths and file-length tiers.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text(
        "paths:\n  ignore:\n    - build/\n    - .venv/\nrules:\n  size.file-length:\n    thresholds:\n      warning: 500\n      error: 1000\n"
    )
    data = load_gruff_py_yaml(path)
    assert data["paths"]["ignore"] == ["build/", ".venv/"]
    assert data["rules"]["size.file-length"]["thresholds"]["warning"] == 500


def test_empty_file_returns_empty_dict(tmp_path: Path):
    """Read an empty YAML file as an empty mapping.

    Args:
        tmp_path: Holds an empty config file.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("")
    assert load_gruff_py_yaml(path) == {}


def test_comments_only_returns_empty_dict(tmp_path: Path):
    """Read a comment-only YAML file as an empty mapping.

    Args:
        tmp_path: Holds a config of comments only.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("# just comments\n# more comments\n")
    assert load_gruff_py_yaml(path) == {}


def test_list_at_root_raises_config_error(tmp_path: Path):
    """Refuse a YAML file whose top level is a list.

    Args:
        tmp_path: Holds a config whose top level is a list.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("- foo\n- bar\n")
    with pytest.raises(ConfigError, match="top-level must be a mapping"):
        load_gruff_py_yaml(path)


def test_invalid_yaml_raises_config_error(tmp_path: Path):
    """Report malformed YAML as a ``ConfigError``.

    Args:
        tmp_path: Holds a config with invalid nesting.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("paths:\n  ignore:\n  -  - nested-bad: x: y\n")
    with pytest.raises(ConfigError, match="Failed to parse YAML"):
        load_gruff_py_yaml(path)


def test_missing_file_raises_config_error(tmp_path: Path):
    """Report a missing YAML file as a ``ConfigError``.

    Args:
        tmp_path: Directory where the named config is never written.
    """
    with pytest.raises(ConfigError, match="Failed to read config file"):
        load_gruff_py_yaml(tmp_path / "does-not-exist.yaml")


def test_dotted_rule_keys_preserved(tmp_path: Path):
    """Keep dotted rule ids as whole keys under ``rules``.

    Args:
        tmp_path: Holds a config with two dotted rule sections.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("rules:\n  size.file-length:\n    enabled: true\n  complexity.cyclomatic:\n    thresholds:\n      warning: 8\n")
    data = load_gruff_py_yaml(path)
    assert "size.file-length" in data["rules"]
    assert "complexity.cyclomatic" in data["rules"]
    assert data["rules"]["complexity.cyclomatic"]["thresholds"]["warning"] == 8
