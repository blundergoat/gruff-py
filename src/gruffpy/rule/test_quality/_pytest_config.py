"""Read pytest and coverage configuration from the project's ``pyproject.toml``.

Project-config rules consume :func:`read_pytest_config` to check whether the
project pins strict-config flags, escalates deprecation warnings, and declares
a coverage source. Results are cached per project root via a WeakValueDictionary
so concurrent rules share the parse.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PytestConfig:
    """Snapshot of pytest-relevant config in a project."""

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
    """Return the cached :class:`PytestConfig` for *project_root*."""
    if project_root in _cache:
        return _cache[project_root]
    config = _read(project_root)
    _cache[project_root] = config
    return config


def reset_cache() -> None:
    """Test-only — clear the per-root cache."""
    _cache.clear()


def _read(project_root: str) -> PytestConfig:
    path = Path(project_root) / "pyproject.toml"
    if not path.is_file():
        return PytestConfig()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return PytestConfig()

    tool = data.get("tool", {})
    pytest_section = tool.get("pytest", {}).get("ini_options", {})
    coverage_section = tool.get("coverage", {}).get("run", {})

    addopts = _split_str(pytest_section.get("addopts"))
    filterwarnings = _string_list(pytest_section.get("filterwarnings"))
    coverage_source = _string_list(coverage_section.get("source"))

    return PytestConfig(
        addopts=tuple(addopts),
        filterwarnings=tuple(filterwarnings),
        coverage_source=tuple(coverage_source),
        is_present=True,
    )


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
