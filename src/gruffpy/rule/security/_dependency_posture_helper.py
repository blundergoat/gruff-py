"""Shared dependency-declaration extraction for supply-chain posture rules."""

import ast
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import parse_qs, urlsplit

from gruffpy.parser.analysis_unit import AnalysisUnit

_REQUIREMENTS_OPTION_PREFIXES = (
    "-c",
    "--constraint",
    "-f",
    "--find-links",
    "-i",
    "--index-url",
    "--extra-index-url",
    "--no-binary",
    "--no-index",
    "--only-binary",
    "--prefer-binary",
    "--pre",
    "-r",
    "--requirement",
    "--trusted-host",
    "-U",
    "--upgrade",
)
_EDITABLE_PREFIXES = ("-e ", "--editable ")
_NAME_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?")
_DIRECT_NAME_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*@\s*(?P<ref>\S+)"
)


@dataclass(frozen=True, slots=True)
class DependencyDeclaration:
    """One dependency declaration found in package metadata or requirements files.

    Attributes:
        raw: Normalised dependency text with comments/options removed.
        line: One-based source line for the declaration.
        source_label: File-format label used in finding security metadata.
    """

    raw: str
    line: int
    source_label: str


def dependency_declarations(unit: AnalysisUnit) -> tuple[DependencyDeclaration, ...]:
    """Extract dependency declarations from the supported metadata file types.

    Args:
        unit: Parsed analysis unit whose raw source text is available.

    Returns:
        Dependency declarations from PEP 621 ``pyproject.toml``, requirements
        files, ``setup.cfg``, or ``setup.py``. Unsupported files return an empty
        tuple.
    """
    display_path = unit.file.display_path.replace("\\", "/")
    filename = PurePosixPath(display_path).name.lower()
    if filename == "pyproject.toml":
        return _pyproject_declarations(unit.source)
    if _is_requirements_file(filename):
        return _requirements_declarations(unit.source)
    if filename == "setup.cfg":
        return _setup_config_declarations(unit.source)
    if filename == "setup.py":
        return _setup_py_declarations(unit)
    return ()


def dependency_name(declaration: DependencyDeclaration) -> str | None:
    """Return the declared package name when it can be recovered safely.

    Args:
        declaration: Dependency declaration to inspect.

    Returns:
        Package/project name, or ``None`` for anonymous URL/local path entries.
    """
    spec = declaration.raw.strip()
    direct = _DIRECT_NAME_RE.match(spec)
    if direct is not None:
        return _normalise_name(direct.group("name"))
    egg = _egg_name(spec)
    if egg is not None:
        return egg
    match = _NAME_RE.match(spec)
    if match is not None and not _looks_like_reference(spec):
        return _normalise_name(match.group("name"))
    return None


def is_git_reference(declaration: DependencyDeclaration) -> bool:
    """Return whether the declaration installs from a Git/VCS reference.

    Args:
        declaration: Dependency declaration to inspect.

    Returns:
        True for ``git+...`` requirement forms and PEP 508 ``name @ git+...`` references.
    """
    lowered = declaration.raw.lower()
    return lowered.startswith("git+") or " @ git+" in lowered or lowered.startswith("git@")


def is_local_path_reference(declaration: DependencyDeclaration) -> bool:
    """Return whether the declaration installs from a local filesystem reference.

    Args:
        declaration: Dependency declaration to inspect.

    Returns:
        True for editable/local paths and PEP 508 ``file:`` references.
    """
    spec = declaration.raw.strip()
    lowered = spec.lower()
    direct = _DIRECT_NAME_RE.match(spec)
    reference = direct.group("ref") if direct is not None else spec
    ref_lowered = reference.lower()
    return (
        ref_lowered.startswith("file:")
        or reference.startswith(("./", "../", "/", "~/"))
        or bool(re.match(r"^[A-Za-z]:[/\\]", reference))
        or (not _looks_like_named_requirement(spec) and "/" in reference and "://" not in reference)
        or lowered.startswith("path:")
    )


def is_url_reference(declaration: DependencyDeclaration) -> bool:
    """Return whether the declaration installs from a non-VCS HTTP(S) URL.

    Args:
        declaration: Dependency declaration to inspect.

    Returns:
        True for direct HTTP(S) references that are not Git/VCS or local-file references.
    """
    if is_git_reference(declaration) or is_local_path_reference(declaration):
        return False
    spec = declaration.raw.strip()
    direct = _DIRECT_NAME_RE.match(spec)
    reference = direct.group("ref") if direct is not None else spec
    lowered = reference.lower()
    return lowered.startswith(("http://", "https://"))


def dependency_label(declaration: DependencyDeclaration) -> str:
    """Return a human-readable dependency label that never includes raw references.

    Args:
        declaration: Dependency declaration to describe.

    Returns:
        ``dependency `<name>``` when a name is available, otherwise
        ``dependency declaration``.
    """
    name = dependency_name(declaration)
    if name is None:
        return "dependency declaration"
    return f"dependency `{name}`"


def dependency_metadata(
    declaration: DependencyDeclaration,
    *,
    reference_kind: str | None = None,
    constraint_kind: str | None = None,
) -> dict[str, str]:
    """Return safe finding metadata for a dependency declaration.

    Args:
        declaration: Dependency declaration to describe.
        reference_kind: Optional reference category such as ``direct-url``.
        constraint_kind: Optional unpinned constraint category.

    Returns:
        Metadata containing only source/category fields and a safe package name
        when one can be recovered.
    """
    metadata = {"dependencySource": declaration.source_label}
    name = dependency_name(declaration)
    if name is not None:
        metadata["dependencyName"] = name
    if reference_kind is not None:
        metadata["referenceKind"] = reference_kind
    if constraint_kind is not None:
        metadata["constraintKind"] = constraint_kind
    return metadata


def _pyproject_declarations(source: str) -> tuple[DependencyDeclaration, ...]:
    """Extract PEP 621 dependency arrays from ``pyproject.toml`` text."""
    try:
        data = tomllib.loads(source)
    except tomllib.TOMLDecodeError:
        return ()
    values: list[str] = []
    project = data.get("project")
    if isinstance(project, dict):
        values.extend(_string_list(project.get("dependencies")))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group_values in optional.values():
                values.extend(_string_list(group_values))
    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        values.extend(_string_list(build_system.get("requires")))
    dependency_groups = data.get("dependency-groups")
    if isinstance(dependency_groups, dict):
        for group_values in dependency_groups.values():
            values.extend(_string_list(group_values))

    used_offsets: set[int] = set()
    return tuple(
        DependencyDeclaration(value, _line_for_value(source, value, used_offsets), "pyproject")
        for value in values
    )


def _requirements_declarations(source: str) -> tuple[DependencyDeclaration, ...]:
    """Extract dependency lines from pip requirements-style text."""
    declarations: list[DependencyDeclaration] = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        cleaned = _normalise_requirement_line(line)
        if cleaned:
            declarations.append(DependencyDeclaration(cleaned, line_no, "requirements"))
    return tuple(declarations)


def _setup_config_declarations(source: str) -> tuple[DependencyDeclaration, ...]:
    """Extract dependency lines from ``setup.cfg`` options sections."""
    declarations: list[DependencyDeclaration] = []
    section = ""
    collecting = False
    for line_no, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]").lower()
            collecting = False
            continue
        if section == "options":
            collecting = _should_continue_setup_config_option_collection(
                stripped,
                line,
                line_no,
                declarations,
                collecting,
            )
        elif section == "options.extras_require":
            collecting = _should_continue_setup_config_extra_collection(
                stripped,
                line,
                line_no,
                declarations,
                collecting,
            )
        else:
            collecting = False
    return tuple(declarations)


def _setup_py_declarations(unit: AnalysisUnit) -> tuple[DependencyDeclaration, ...]:
    """Extract literal dependency strings from ``setup(...)`` calls in ``setup.py``."""
    if unit.tree is None:
        return ()
    declarations: list[DependencyDeclaration] = []
    for node in ast.walk(unit.tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg not in {
                "install_requires",
                "setup_requires",
                "tests_require",
                "extras_require",
            }:
                continue
            declarations.extend(_dependency_values_from_ast(keyword.value))
    return tuple(declarations)


def _dependency_values_from_ast(node: ast.AST) -> list[DependencyDeclaration]:
    """Return literal dependency strings nested inside a setup keyword value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [DependencyDeclaration(node.value, node.lineno, "setup.py")]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[DependencyDeclaration] = []
        for item in node.elts:
            values.extend(_dependency_values_from_ast(item))
        return values
    if isinstance(node, ast.Dict):
        values = []
        for value in node.values:
            values.extend(_dependency_values_from_ast(value))
        return values
    return []


def _should_continue_setup_config_option_collection(
    stripped: str,
    raw_line: str,
    line_no: int,
    declarations: list[DependencyDeclaration],
    collecting: bool,
) -> bool:
    """Collect ``install_requires`` continuation lines in a setup.cfg options section."""
    if stripped.startswith("install_requires"):
        _, _, after = stripped.partition("=")
        cleaned = _normalise_requirement_line(after)
        if cleaned:
            declarations.append(DependencyDeclaration(cleaned, line_no, "setup.cfg"))
        return True
    if collecting and raw_line[:1].isspace():
        cleaned = _normalise_requirement_line(stripped)
        if cleaned:
            declarations.append(DependencyDeclaration(cleaned, line_no, "setup.cfg"))
        return True
    return False


def _should_continue_setup_config_extra_collection(
    stripped: str,
    raw_line: str,
    line_no: int,
    declarations: list[DependencyDeclaration],
    collecting: bool,
) -> bool:
    """Collect dependency continuation lines in a setup.cfg extras section."""
    if "=" in stripped and not raw_line[:1].isspace():
        _, _, after = stripped.partition("=")
        cleaned = _normalise_requirement_line(after)
        if cleaned:
            declarations.append(DependencyDeclaration(cleaned, line_no, "setup.cfg"))
        return True
    if collecting and raw_line[:1].isspace():
        cleaned = _normalise_requirement_line(stripped)
        if cleaned:
            declarations.append(DependencyDeclaration(cleaned, line_no, "setup.cfg"))
        return True
    return False


def _normalise_requirement_line(line: str) -> str:
    """Return a requirement declaration with comments/options stripped, or ``""``."""
    stripped = re.sub(r"\s+#.*$", "", line).strip()
    if not stripped or stripped.startswith("#"):
        return ""
    for prefix in _REQUIREMENTS_OPTION_PREFIXES:
        if stripped == prefix or stripped.startswith(prefix + " "):
            return ""
    for prefix in _EDITABLE_PREFIXES:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :].strip()
            break
    stripped = re.split(r"\s+--hash(?:=|\s)", stripped, maxsplit=1)[0].strip()
    return stripped


def _string_list(value: object) -> list[str]:
    """Return string list items from a parsed TOML value."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _line_for_value(source: str, value: str, used_offsets: set[int]) -> int:
    """Return the source line containing a TOML string value."""
    patterns = (f'"{value}"', f"'{value}'")
    for pattern in patterns:
        start = 0
        while True:
            offset = source.find(pattern, start)
            if offset < 0:
                break
            if offset not in used_offsets:
                used_offsets.add(offset)
                return source.count("\n", 0, offset) + 1
            start = offset + len(pattern)
    offset = source.find(value)
    return source.count("\n", 0, max(offset, 0)) + 1


def _call_name(node: ast.AST) -> str:
    """Return the terminal call name for a setup.py call expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_requirements_file(filename: str) -> bool:
    """Return whether *filename* is a pip requirements-style file."""
    return filename.startswith("requirements") and filename.endswith((".txt", ".in"))


def _normalise_name(name: str) -> str:
    """Return a normalised package-name spelling for metadata."""
    return name.replace("_", "-").lower()


def _egg_name(spec: str) -> str | None:
    """Return a ``#egg=`` package name from a URL requirement if present."""
    fragment = urlsplit(spec).fragment
    if not fragment:
        return None
    values = parse_qs(fragment).get("egg")
    if not values:
        return None
    return _normalise_name(values[0])


def _looks_like_reference(spec: str) -> bool:
    """Return whether the declaration starts with a URL, VCS, or local path."""
    lowered = spec.lower()
    return (
        "://" in spec
        or lowered.startswith(("git+", "git@", "file:"))
        or spec.startswith(("./", "../", "/", "~/"))
        or bool(re.match(r"^[A-Za-z]:[/\\]", spec))
    )


def _looks_like_named_requirement(spec: str) -> bool:
    """Return whether the declaration starts with a package-name token."""
    return _NAME_RE.match(spec) is not None and not _looks_like_reference(spec)
