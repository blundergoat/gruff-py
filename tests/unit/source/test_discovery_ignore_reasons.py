"""Tests for ignore-reason reporting and the shared ``SourceDiscovery.classify`` engine."""

from pathlib import Path

from gruffpy.source.discovery import IgnoredPath, SourceDiscovery


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_hidden_sources(parent: Path, directory_names: tuple[str, ...]) -> None:
    """Place one Python file inside each named directory, so discovery has something to skip.

    Args:
        parent: Directory the named directories are created under.
        directory_names: Directory names the fallback policy is expected to ignore.
    """
    for name in directory_names:
        _write(parent / name / "hidden.py")


def test_classify_reports_config_source_and_matched_pattern(tmp_path: Path) -> None:
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).classify("gen/out.py", configured_ignore_patterns=["gen/**"])

    assert result == IgnoredPath(path="gen/out.py", source="config", pattern="gen/**")


def test_classify_config_match_wins_even_with_include_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).classify("gen/out.py", include_ignored=True, configured_ignore_patterns=["gen/**"])

    assert result is not None
    assert result.source == "config"


def test_classify_reports_default_directory_source(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()

    result = SourceDiscovery(tmp_path).classify("node_modules")

    assert result == IgnoredPath(path="node_modules", source="default", pattern="node_modules")


def test_classify_existing_file_uses_explicit_semantics(tmp_path: Path) -> None:
    _write(tmp_path / ".gitignore", "secret.py\n")
    _write(tmp_path / "secret.py")

    result = SourceDiscovery(tmp_path).classify("secret.py")

    assert result is None


def test_classify_does_not_ignore_lockfile_by_filename(tmp_path: Path) -> None:
    result = SourceDiscovery(tmp_path).classify("uv.lock")

    assert result is None


def test_classify_returns_none_for_non_ignored_path(tmp_path: Path) -> None:
    assert SourceDiscovery(tmp_path).classify("src/app.py") is None


def test_classify_works_on_hypothetical_path_not_on_disk(tmp_path: Path) -> None:
    result = SourceDiscovery(tmp_path).classify("gen/missing.py", configured_ignore_patterns=["gen/**"])

    assert result is not None
    assert result.source == "config"


def test_discover_records_ignore_reason_for_explicit_config_match(tmp_path: Path) -> None:
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["gen/out.py"], configured_ignore_patterns=["gen/**"])

    assert result.files == ()
    assert result.ignored_paths == ("gen/out.py",)
    assert result.ignored_path_reasons == (IgnoredPath(path="gen/out.py", source="config", pattern="gen/**"),)


def test_explicit_ineligible_lockfile_is_not_reported_as_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "uv.lock", "# lock\n")

    result = SourceDiscovery(tmp_path).discover(["uv.lock"])

    assert result.files == ()
    assert result.ignored_path_reasons == ()


def test_walk_treats_ineligible_lockfile_as_unsupported_not_ignored(tmp_path: Path) -> None:
    _write(tmp_path / "uv.lock", "# lock\n")
    _write(tmp_path / "app.py", "x = 1\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert [source.display_path for source in result.files] == ["app.py"]
    assert result.ignored_path_reasons == ()


def test_eligible_json_lockfile_is_scanned(tmp_path: Path) -> None:
    _write(tmp_path / "package-lock.json", "{}\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert [source.display_path for source in result.files] == ["package-lock.json"]


def test_vcs_internals_remain_blocked_for_explicit_file_and_include_ignored(
    tmp_path: Path,
) -> None:
    _write(tmp_path / ".git" / "config.py")

    result = SourceDiscovery(tmp_path).discover([".git/config.py"], include_ignored=True)

    assert result.files == ()
    assert result.ignored_path_reasons == (IgnoredPath(path=".git/config.py", source="default", pattern=".git"),)


def test_python_fallback_exceptions_apply_at_any_depth(tmp_path: Path) -> None:
    ignored_names = (
        ".mypy_cache",
        ".pyre",
        ".pytest_cache",
        ".pytype",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "htmlcov",
        "venv",
    )
    _write_hidden_sources(tmp_path / "nested", ignored_names)
    _write(tmp_path / "cache" / "visible.py")
    _write(tmp_path / "generated" / "visible.py")
    _write(tmp_path / ".goat-flow" / "visible.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {
        ".goat-flow/visible.py",
        "cache/visible.py",
        "generated/visible.py",
    }
    assert {reason.pattern for reason in result.ignored_path_reasons} == set(ignored_names)


def test_discover_ignored_paths_remains_plain_strings(tmp_path: Path) -> None:
    _write(tmp_path / "gen" / "out.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."], configured_ignore_patterns=["gen/**"])

    assert all(isinstance(path, str) for path in result.ignored_paths)
    assert "gen/out.py" in result.ignored_paths


def test_third_party_directories_are_skipped_under_a_governing_gitignore(tmp_path: Path) -> None:
    """Section 7 (precision-floor M04): copied and built code is skipped at any depth, whatever the .gitignore says.

    Args:
        tmp_path: Synthetic project root.
    """
    _write(tmp_path / ".gitignore", "*.log\n")
    for directory in ("vendor", "Vendors", "pkg/THIRD_PARTY", "pkg/third-party", "web/bower_components", "app/Dist"):
        _write(tmp_path / directory / "copied.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {"src/app.py"}
    assert {(reason.path, reason.source, reason.pattern) for reason in result.ignored_path_reasons} == {
        ("vendor", "default", "vendor"),
        ("Vendors", "default", "vendors"),
        ("pkg/THIRD_PARTY", "default", "third_party"),
        ("pkg/third-party", "default", "third-party"),
        ("web/bower_components", "default", "bower_components"),
        ("app/Dist", "default", "dist"),
    }


def test_outermost_third_party_directory_names_the_reason(tmp_path: Path) -> None:
    _write(tmp_path / "vendor" / "lib" / "dist" / "copied.py")

    result = SourceDiscovery(tmp_path).classify("vendor/lib/dist/copied.py", include_ignored=False)

    # An existing file operand bypasses the classes, so the hypothetical sibling carries the path-policy verdict.
    assert result is None
    assert SourceDiscovery(tmp_path).classify("vendor/lib/dist/other.py") == IgnoredPath(
        path="vendor/lib/dist/other.py", source="default", pattern="vendor"
    )


def test_minified_files_are_skipped_and_listed_only_when_eligible(tmp_path: Path) -> None:
    _write(tmp_path / "config" / "settings.min.json", "{}")
    _write(tmp_path / "static" / "jquery.min.js", "var a=1;")
    _write(tmp_path / "config" / "settings.json", "{}")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {"config/settings.json"}
    # py never scans .js, so the minified script is unsupported rather than listed as ignored.
    assert result.ignored_path_reasons == (IgnoredPath(path="config/settings.min.json", source="default", pattern="*.min.*"),)


def test_include_ignored_and_explicit_files_bring_the_classes_back(tmp_path: Path) -> None:
    _write(tmp_path / "vendor" / "copied.py")
    _write(tmp_path / "dist" / "built.py")
    _write(tmp_path / "config" / "settings.min.json", "{}")

    included = SourceDiscovery(tmp_path).discover(["."], include_ignored=True)
    explicit = SourceDiscovery(tmp_path).discover(["vendor/copied.py", "config/settings.min.json"])

    assert {source.display_path for source in included.files} == {"vendor/copied.py", "dist/built.py", "config/settings.min.json"}
    assert {source.display_path for source in explicit.files} == {"vendor/copied.py", "config/settings.min.json"}


def test_first_party_names_that_only_resemble_the_classes_stay_in_scope(tmp_path: Path) -> None:
    for relative in (
        "src/vendor_api.py",
        "src/vendors.py",
        "src/dist.py",
        "build/scripts/release.py",
        "lib/helpers.py",
        "external/typings.py",
        "src/admin.mini.py",
        "src/min.py",
    ):
        _write(tmp_path / relative)
    _write(tmp_path / ".gitignore", "*.log\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {
        "src/vendor_api.py",
        "src/vendors.py",
        "src/dist.py",
        "build/scripts/release.py",
        "lib/helpers.py",
        "external/typings.py",
        "src/admin.mini.py",
        "src/min.py",
    }
