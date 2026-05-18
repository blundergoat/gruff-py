"""``.gruff-py.yaml`` loader (ADR-006).

Parses a YAML file into the same ``dict`` shape ``ConfigLoader._apply`` accepts
from ``pyproject.toml`` ``[tool.gruff-py]``. The YAML uses the same option keys
as the TOML form (camelCase top-level + nested rule-id keys).
"""

from pathlib import Path
from typing import Any

import yaml

from gruffpy.config.exceptions import ConfigError


def load_gruff_py_yaml(path: Path) -> dict[str, Any]:
    """Return the parsed dict at *path*, or ``{}`` if the file is empty.

    Raises ``ConfigError`` on:

    - I/O errors;
    - YAML parse errors;
    - a top-level value that isn't a mapping (e.g. a list at the file root).
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except OSError as exc:
        raise ConfigError(f"Failed to read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML in {path}: {exc}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top-level must be a mapping, got {type(raw).__name__}.")
    return raw
