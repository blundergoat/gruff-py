from pathlib import Path

import pytest

from gruffpy.analysis.runner import _scan_scope


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        ((), "full-project"),
        ((".",), "full-project"),
        (("./",), "full-project"),
        (("src/..",), "full-project"),
        ((".", "src"), "full-project"),
        (("src", "."), "full-project"),
        (("src",), "partial-scope"),
        (("src", "tests"), "partial-scope"),
    ],
    ids=[
        "empty",
        "just-dot",
        "dot-slash",
        "dot-dot-roundtrip",
        "dot-then-subdir",
        "subdir-then-dot",
        "single-subdir",
        "two-subdirs",
    ],
)
def test_scan_scope_treats_project_root_paths_as_full_project(tmp_path: Path, paths: tuple[str, ...], expected: str) -> None:
    """Classify a scan as full-project when its operands are empty or include the project root, and as partial scope otherwise.

    Args:
        tmp_path: Project root the operands are resolved against.
        paths: Scan operands; the cases cover no operand, spellings of the root, the root beside a folder, and folders alone.
        expected: Scope the case must produce.
    """
    assert _scan_scope(paths, tmp_path) == expected


def test_scan_scope_treats_absolute_project_root_as_full_project(tmp_path: Path) -> None:
    """Treat the project root's absolute path as full-project and an absolute subfolder path as partial scope.

    Args:
        tmp_path: Project root, passed by its absolute path and then with a ``src`` suffix.
    """
    assert _scan_scope((str(tmp_path),), tmp_path) == "full-project"
    assert _scan_scope((str(tmp_path / "src"),), tmp_path) == "partial-scope"
