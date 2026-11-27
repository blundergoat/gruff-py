"""Read pytest and coverage configuration for a project root.

Project-config rules use :func:`read_pytest_config` to check ``pyproject.toml`` for strict-config flags, deprecation filters and coverage source.
``test-quality.no-assertions`` reads ``python_files`` from ``pytest.ini``, ``pyproject.toml``, ``tox.ini`` or ``setup.cfg``, in pytest's order.

Results are cached per project root in a module-level dictionary.
"""

import configparser
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PytestConfig:
    """Snapshot of pytest and coverage settings for one scanned project root.

    Project-config rules read ``addopts``, ``filterwarnings``, and ``coverage_source`` from ``pyproject.toml`` when ``is_present`` is True.
    ``test-quality.no-assertions`` reads ``python_files`` using pytest's config precedence even when ``pyproject.toml`` has no pytest table.

    Attributes:
        addopts: Parsed ``tool.pytest.ini_options.addopts`` tokens; empty when omitted or when ``pyproject.toml`` has no pytest table.
        filterwarnings: Pytest warning-filter entries from ``pyproject.toml``; empty when omitted.
        coverage_source: Coverage source package entries from ``pyproject.toml``; empty when omitted.
        python_files: Configured ``python_files`` collection globs from the winning pytest config file; empty means pytest defaults apply.
        is_present: True only when ``pyproject.toml`` defines ``[tool.pytest.ini_options]``.
    """

    addopts: tuple[str, ...] = ()
    filterwarnings: tuple[str, ...] = ()
    coverage_source: tuple[str, ...] = ()
    python_files: tuple[str, ...] = ()
    is_present: bool = False

    def has_strict_config(self) -> bool:
        """Check whether pytest addopts contains a strict configuration or marker flag.

        Either --strict-config or --strict-markers satisfies this rule's strictness check; both are not required.

        Returns:
            True when addopts contains either flag, otherwise False; the other strictness protection may still be disabled.
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
            any(line.startswith("error") and "DeprecationWarning" in line for line in self.filterwarnings)
            or any(line.startswith("error::") and "DeprecationWarning" in line for line in self.filterwarnings)
            or any(line.strip() == "error" for line in self.filterwarnings)
        )

    def has_coverage_source(self) -> bool:
        """Return whether the coverage source allowlist contains any entries.

        Returns:
            True for a nonempty coverage_source tuple, otherwise False; entry contents are not validated.
        """
        return bool(self.coverage_source)


_cache: dict[str, PytestConfig] = {}


def read_pytest_config(project_root: str) -> PytestConfig:
    """Return pytest and coverage settings, caching the first snapshot for each project-root string.

    Args:
        project_root: Path to the project root containing pyproject.toml; the exact string is the shared-cache key.

    Returns:
        Parsed settings, or an empty snapshot for a missing file, caught OSError, TOML parse error or absent tool table.
        Later calls for the same root reuse that snapshot until reset_cache clears the shared cache.

    Raises:
        UnicodeDecodeError: When pyproject.toml contains invalid UTF-8.
    """
    if project_root in _cache:
        return _cache[project_root]
    config = _read(project_root)
    _cache[project_root] = config
    return config


def reset_cache() -> None:
    """Test-only - clear the per-root cache.

    Returns:
        None. Clears the shared per-root settings cache.
    """
    _cache.clear()


def _read(project_root: str) -> PytestConfig:
    """Read pytest and coverage settings for a project root without caching.

    ``is_present``, ``addopts``, ``filterwarnings``, and ``coverage_source`` come from
    ``pyproject.toml``. ``python_files`` follows pytest's config-file precedence across
    ``pytest.ini``, ``pyproject.toml``, ``tox.ini``, and ``setup.cfg``.

    Args:
        project_root: Directory containing the project configuration files to read.

    Returns:
        A snapshot of supported settings. Missing or unreadable files leave the corresponding fields empty.
        Without ``tool.pytest.ini_options`` in ``pyproject.toml``, ``is_present`` is False even if INI files or coverage settings exist.
    """
    root = Path(project_root)
    pytest_section, coverage_section = _read_pyproject_sections(root / "pyproject.toml")

    addopts = _split_str(_table_value(pytest_section, "addopts"))
    filterwarnings = _string_list(_table_value(pytest_section, "filterwarnings"))
    coverage_source = _string_list(_table_value(coverage_section, "source"))
    python_files = _resolve_python_files(root, pytest_section)

    return PytestConfig(
        addopts=tuple(addopts),
        filterwarnings=tuple(filterwarnings),
        coverage_source=tuple(coverage_source),
        python_files=python_files,
        is_present=pytest_section is not None,
    )


def _read_pyproject_sections(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Read the pytest and coverage tables from ``pyproject.toml`` when present and valid.

    Args:
        path: Path to ``pyproject.toml`` under the project root.

    Returns:
        Tuple of ``(tool.pytest.ini_options, tool.coverage.run)`` tables, each None when missing or unreadable.
    """
    # A project without pyproject.toml has no pytest or coverage tables to read.
    if not path.is_file():
        return None, None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        # For example, a broken or unreadable pyproject.toml leaves pytest project-config checks inactive instead of aborting `analyse`.
        return None, None
    tool = _as_table(data.get("tool"))
    # A pyproject.toml without a [tool] table configures neither pytest nor coverage.
    if tool is None:
        return None, None
    return _nested_table(tool, "pytest", "ini_options"), _nested_table(tool, "coverage", "run")


def _resolve_python_files(root: Path, pyproject_pytest_section: dict[str, Any] | None) -> tuple[str, ...]:
    """Resolve ``python_files`` globs from the four pytest config sources gruff reads, in pytest's precedence order.

    ``pytest.ini`` wins as soon as it exists, then ``pyproject.toml`` ``[tool.pytest.ini_options]``, ``tox.ini`` ``[pytest]`` and ``setup.cfg``.
    Other pytest sources, such as ``.pytest.ini``, are not read, so a project that sets ``python_files`` only there gets the default globs.

    Args:
        root: Project root directory holding candidate pytest config files.
        pyproject_pytest_section: Parsed ``[tool.pytest.ini_options]`` table, or None when absent.

    Returns:
        Configured ``python_files`` globs from the winning config source, or empty when pytest defaults apply.
    """
    pytest_ini = root / "pytest.ini"
    # An existing pytest.ini takes precedence over pyproject.toml, tox.ini, and setup.cfg even when empty.
    if pytest_ini.is_file():
        return _ini_section_python_files(pytest_ini, "pytest") or ()
    # pyproject.toml wins next whenever it has a [tool.pytest.ini_options] table, even one without python_files.
    if pyproject_pytest_section is not None:
        return tuple(_split_str(_table_value(pyproject_pytest_section, "python_files")))
    # Then tox.ini and setup.cfg are tried in pytest's order; the first with a pytest section wins.
    for filename, section in (("tox.ini", "pytest"), ("setup.cfg", "tool:pytest")):
        globs = _ini_section_python_files(root / filename, section)
        if globs is not None:
            return globs
    return ()


def _ini_section_python_files(path: Path, section: str) -> tuple[str, ...] | None:
    """Read ``python_files`` from one INI config section if the file exists and defines that section.

    Args:
        path: Candidate INI configuration file.
        section: Section header name to inspect, such as ``pytest`` or ``tool:pytest``.

    Returns:
        Tuple of globs when the section exists (empty if the key is absent), or None when the file or section is absent or unreadable.
    """
    # A missing INI file passes the search on to the next pytest config source.
    if not path.is_file():
        return None
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, configparser.Error):
        # For example, a legacy Latin-1 or syntactically invalid setup.cfg falls through to the next source or pytest defaults.
        return None
    # A file without the pytest section, such as a tox.ini used only for tox, does not configure pytest.
    if not parser.has_section(section):
        return None
    return tuple(_split_str(parser.get(section, "python_files", fallback=None)))


def _as_table(value: object) -> dict[str, Any] | None:
    """Accept a decoded TOML value only when it is a dictionary.

    Args:
        value: Decoded value whose table shape is checked without validating its contents.

    Returns:
        The same dictionary object, or None for a non-dictionary value.
    """
    if isinstance(value, dict):
        return value
    return None


def _nested_table(table: dict[str, Any], outer_key: str, inner_key: str) -> dict[str, Any] | None:
    """Look up a two-level dictionary section in decoded TOML.

    Args:
        table: Outer decoded table from which the section is read.
        outer_key: Key whose value must be the intermediate dictionary.
        inner_key: Key in the intermediate dictionary whose value must be the requested table.

    Returns:
        The original inner dictionary, or None when either key is missing or either value is not a dictionary.
    """
    outer = _as_table(table.get(outer_key))
    if outer is None:
        return None
    return _as_table(outer.get(inner_key))


def _table_value(table: dict[str, Any] | None, key: str) -> object:
    """Read an optional configuration table entry.

    Args:
        table: Decoded table to inspect, or None when its section is absent.
        key: Configuration key to look up in the supplied table.

    Returns:
        The stored value, or None when the table or key is absent.
    """
    if table is None:
        return None
    return table.get(key)


def _split_str(value: object) -> list[str]:
    """Split a TOML option into whitespace tokens or stringified list entries.

    Args:
        value: Decoded option value; strings are split on whitespace and list elements are converted with str.

    Returns:
        Whitespace-delimited tokens for a string, stringified elements for a list, or an empty list for other values.
    """
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _string_list(value: object) -> list[str]:
    """Coerce a TOML value to a list of strings.

    Args:
        value: Decoded option value; a string is kept as one entry and list elements are converted with str.

    Returns:
        Stringified list elements, a single unchanged string entry, or an empty list for other values.
    """
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []
