"""Unit tests for ``GitignoreMatcher`` covering layered/nested gitignore rules."""

from pathlib import Path

from gruffpy.source.gitignore import GitignoreMatcher


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_no_gitignore_means_nothing_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "a.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert not matcher.has_rules()
    assert matcher.is_ignored(tmp_path / "a.py") is False


def test_root_gitignore_matches_file_at_root(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "ignored.txt\n")
    _write(tmp_path / "ignored.txt")
    _write(tmp_path / "kept.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "ignored.txt") is True
    assert matcher.is_ignored(tmp_path / "kept.py") is False


def test_directory_pattern_requires_is_dir_flag(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "build/\n")
    (tmp_path / "build").mkdir()
    _write(tmp_path / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "build", is_dir=True) is True
    assert matcher.is_ignored(tmp_path / "build" / "out.py") is True


def test_non_anchored_pattern_matches_at_any_depth(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "build/\n")
    (tmp_path / "pkg" / "build").mkdir(parents=True)
    _write(tmp_path / "pkg" / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "pkg" / "build", is_dir=True) is True
    assert matcher.is_ignored(tmp_path / "pkg" / "build" / "out.py") is True


def test_anchored_pattern_matches_only_at_root(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "/build/\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "pkg" / "build").mkdir(parents=True)
    _write(tmp_path / "build" / "out.py")
    _write(tmp_path / "pkg" / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "build" / "out.py") is True
    assert matcher.is_ignored(tmp_path / "pkg" / "build" / "out.py") is False


def test_negation_pattern_re_includes(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.bin\n!keep.bin\n")
    _write(tmp_path / "ignored.bin")
    _write(tmp_path / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "ignored.bin") is True
    assert matcher.is_ignored(tmp_path / "keep.bin") is False


def test_nested_gitignore_overrides_root(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.bin\n")
    _write(tmp_path / "pkg" / ".gitignore", "!keep.bin\n")
    _write(tmp_path / "pkg" / "noise.bin")
    _write(tmp_path / "pkg" / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "pkg" / "noise.bin") is True
    assert matcher.is_ignored(tmp_path / "pkg" / "keep.bin") is False


def test_nested_gitignore_can_re_ignore_what_root_negated(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.bin\n!keep.bin\n")
    _write(tmp_path / "pkg" / ".gitignore", "keep.bin\n")
    _write(tmp_path / "keep.bin")
    _write(tmp_path / "pkg" / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "keep.bin") is False
    assert matcher.is_ignored(tmp_path / "pkg" / "keep.bin") is True


def test_double_star_pattern(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "**/temp/\n")
    (tmp_path / "a" / "temp").mkdir(parents=True)
    (tmp_path / "b" / "deep" / "temp").mkdir(parents=True)
    _write(tmp_path / "a" / "temp" / "file.py")
    _write(tmp_path / "b" / "deep" / "temp" / "file.py")
    _write(tmp_path / "a" / "kept.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "a" / "temp" / "file.py") is True
    assert matcher.is_ignored(tmp_path / "b" / "deep" / "temp" / "file.py") is True
    assert matcher.is_ignored(tmp_path / "a" / "kept.py") is False


def test_path_outside_root_is_not_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "project" / ".gitignore", "*.bin\n")
    _write(tmp_path / "project" / "ignored.bin")
    _write(tmp_path / "sibling.bin")

    matcher = GitignoreMatcher.from_root(tmp_path / "project")

    assert matcher.is_ignored(tmp_path / "project" / "ignored.bin") is True
    assert matcher.is_ignored(tmp_path / "sibling.bin") is False


def test_comment_and_blank_lines_are_tolerated(tmp_path: Path) -> None:
    _write(
        tmp_path / ".gitignore",
        "# leading comment\n\n*.bin\n   \n# trailing comment\n",
    )
    _write(tmp_path / "x.bin")
    _write(tmp_path / "y.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "x.bin") is True
    assert matcher.is_ignored(tmp_path / "y.py") is False


def test_has_rules_reflects_loaded_state(tmp_path: Path) -> None:
    assert GitignoreMatcher.from_root(tmp_path).has_rules() is False

    _write(tmp_path / ".gitignore", "ignored.txt\n")
    assert GitignoreMatcher.from_root(tmp_path).has_rules() is True
