import pytest

from gruffpy.analysis.runner import _scan_scope


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        ((), "full-project"),
        ((".",), "full-project"),
        ((".", "src"), "full-project"),
        (("src", "."), "full-project"),
        (("src",), "partial-scope"),
        (("src", "tests"), "partial-scope"),
    ],
    ids=[
        "empty",
        "just-dot",
        "dot-then-subdir",
        "subdir-then-dot",
        "single-subdir",
        "two-subdirs",
    ],
)
def test_scan_scope_treats_any_dot_path_as_full_project(
    paths: tuple[str, ...], expected: str
) -> None:
    assert _scan_scope(paths) == expected
