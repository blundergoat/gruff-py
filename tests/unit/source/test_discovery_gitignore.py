"""Tests for ``SourceDiscovery`` honoring ``.gitignore`` alongside its other layers."""

from pathlib import Path

from gruffpy.source.discovery import SourceDiscovery


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _display_paths(result_files: tuple, root: Path) -> set[str]:
    return {sf.display_path for sf in result_files}


def test_no_gitignore_means_discovery_unchanged(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "x = 1\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert "src/app.py" in _display_paths(result.files, tmp_path)


def test_gitignored_file_is_excluded_from_discovery(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "src/secret.py\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "src" / "secret.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files, tmp_path)
    assert "src/app.py" in paths
    assert "src/secret.py" not in paths


def test_gitignored_directory_is_reported_in_ignored_paths(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "build/\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "build" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files, tmp_path)
    assert "src/app.py" in paths
    assert "build/out.py" not in paths
    assert "build" in result.ignored_paths


def test_include_ignored_bypasses_gitignore(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "build/\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "build" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["."], include_ignored=True)

    paths = _display_paths(result.files, tmp_path)
    assert "src/app.py" in paths
    assert "build/out.py" in paths


def test_configured_patterns_apply_even_with_include_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "tests" / "fixtures" / "fixture.py")

    result = SourceDiscovery(tmp_path).discover(
        ["."],
        include_ignored=True,
        configured_ignore_patterns=["tests/fixtures/**"],
    )

    paths = _display_paths(result.files, tmp_path)
    assert "src/app.py" in paths
    assert "tests/fixtures/fixture.py" not in paths


def test_nested_gitignore_negation_re_includes_file(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "*.gen.py\n")
    _write(tmp_path / "pkg" / ".gitignore", "!keep.gen.py\n")
    _write(tmp_path / "pkg" / "ignored.gen.py")
    _write(tmp_path / "pkg" / "keep.gen.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files, tmp_path)
    assert "pkg/keep.gen.py" in paths
    assert "pkg/ignored.gen.py" not in paths


def test_explicit_gitignored_path_is_skipped_unless_include_ignored(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "secret.py\n")
    _write(tmp_path / "secret.py")

    default = SourceDiscovery(tmp_path).discover(["secret.py"])
    forced = SourceDiscovery(tmp_path).discover(["secret.py"], include_ignored=True)

    assert "secret.py" not in _display_paths(default.files, tmp_path)
    assert "secret.py" in _display_paths(forced.files, tmp_path)


def test_gitignored_directory_descent_is_skipped(tmp_path: Path) -> None:
    """Gitignored directories must not be walked into (performance + correctness)."""
    _write(tmp_path / ".gitignore", "vendor/\n")
    _write(tmp_path / "vendor" / "a.py")
    _write(tmp_path / "vendor" / "deep" / "b.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files, tmp_path)
    assert "src/app.py" in paths
    assert not any(p.startswith("vendor/") for p in paths)


def test_gitignored_paths_only_directories_appear_in_ignored_summary(tmp_path: Path) -> None:
    """Match the existing convention: files are silently skipped; directories are summarised."""
    _write(tmp_path / ".gitignore", "skip_me.py\nvendor/\n")
    _write(tmp_path / "skip_me.py")
    _write(tmp_path / "vendor" / "lib.py")
    _write(tmp_path / "kept.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert "skip_me.py" not in result.ignored_paths
    assert "vendor" in result.ignored_paths
