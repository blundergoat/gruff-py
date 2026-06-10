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
def test_scan_scope_treats_project_root_paths_as_full_project(
    tmp_path: Path, paths: tuple[str, ...], expected: str
) -> None:
    assert _scan_scope(paths, tmp_path) == expected


def test_scan_scope_treats_absolute_project_root_as_full_project(tmp_path: Path) -> None:
    assert _scan_scope((str(tmp_path),), tmp_path) == "full-project"
    assert _scan_scope((str(tmp_path / "src"),), tmp_path) == "partial-scope"
