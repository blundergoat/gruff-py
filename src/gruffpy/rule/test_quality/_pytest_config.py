"""Read pytest and coverage configuration from the project's ``pyproject.toml``.

Project-config rules consume :func:`read_pytest_config` to check whether the
project pins strict-config flags, escalates deprecation warnings, and declares
a coverage source. Results are cached per project root via a WeakValueDictionary
so concurrent rules share the parse.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PytestConfig:
    """Snapshot of pytest-relevant config in a project.

    Attributes:
        addopts: Parsed ``tool.pytest.ini_options.addopts`` tokens.
        filterwarnings: Pytest warning-filter entries.
        coverage_source: Coverage source package entries.
        is_present: Whether pytest configuration was found.
    """

    addopts: tuple[str, ...] = ()
    filterwarnings: tuple[str, ...] = ()
    coverage_source: tuple[str, ...] = ()
    is_present: bool = False

    def has_strict_config(self) -> bool:
        """Return whether pytest is configured to fail on unknown configs or markers.

        True when either ``--strict-config`` or ``--strict-markers``
        appears in ``addopts``; both pins are treated as equivalent strict
        signals.

        Returns:
            True when pytest will refuse silent config typos.
        """
        return "--strict-config" in self.addopts or "--strict-markers" in self.addopts

    def has_deprecations_as_errors(self) -> bool:
        """Return whether pytest will escalate ``DeprecationWarning`` to an error.

        Accepts three filter shapes: ``error...DeprecationWarning``,
        ``error::...DeprecationWarning``, and a bare ``error`` (which
        escalates *every* warning class, deprecations included).

        Returns:
            True when ``filterwarnings`` would turn a ``DeprecationWarning`` fatal.
        """
        return (
            any(
                line.startswith("error") and "DeprecationWarning" in line
                for line in self.filterwarnings
            )
            or any(
                line.startswith("error::") and "DeprecationWarning" in line
                for line in self.filterwarnings
            )
            or any(line.strip() == "error" for line in self.filterwarnings)
        )

    def has_coverage_source(self) -> bool:
        """Return whether ``[tool.coverage.run] source`` lists at least one package.

        Returns:
            True when coverage has a configured source allowlist.
        """
        return bool(self.coverage_source)


_cache: dict[str, PytestConfig] = {}


def read_pytest_config(project_root: str) -> PytestConfig:
    """Return the cached :class:`PytestConfig` for *project_root*.

    Args:
        project_root: Path to the project root containing ``pyproject.toml``.

    Returns:
        Parsed pytest configuration; subsequent calls reuse the cached value.
    """
    if project_root in _cache:
        return _cache[project_root]
    config = _read(project_root)
    _cache[project_root] = config
    return config


def reset_cache() -> None:
    """Test-only - clear the per-root cache."""
    _cache.clear()


def _read(project_root: str) -> PytestConfig:
    path = Path(project_root) / "pyproject.toml"
    if not path.is_file():
        return PytestConfig()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return PytestConfig()

    tool = _as_table(data.get("tool"))
    if tool is None:
        return PytestConfig()
    pytest_section = _nested_table(tool, "pytest", "ini_options")
    coverage_section = _nested_table(tool, "coverage", "run")

    addopts = _split_str(_table_value(pytest_section, "addopts"))
    filterwarnings = _string_list(_table_value(pytest_section, "filterwarnings"))
    coverage_source = _string_list(_table_value(coverage_section, "source"))

    return PytestConfig(
        addopts=tuple(addopts),
        filterwarnings=tuple(filterwarnings),
        coverage_source=tuple(coverage_source),
        is_present=pytest_section is not None,
    )


def _as_table(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _nested_table(table: dict[str, Any], outer_key: str, inner_key: str) -> dict[str, Any] | None:
    outer = _as_table(table.get(outer_key))
    if outer is None:
        return None
    return _as_table(outer.get(inner_key))


def _table_value(table: dict[str, Any] | None, key: str) -> object:
    if table is None:
        return None
    return table.get(key)


def _split_str(value: object) -> list[str]:
    """Split a TOML ``addopts`` value (either a string or a list)."""
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _string_list(value: object) -> list[str]:
    """Coerce a TOML value to a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []
