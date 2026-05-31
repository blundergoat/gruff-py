"""Source discovery coverage for dependency metadata files."""

from pathlib import Path

from gruffpy.source.discovery import SourceDiscovery


def test_dependency_metadata_files_are_discovered_as_text(tmp_path: Path) -> None:
    """Requirements and setup.cfg files enter text analysis without broad .txt scans.

    Args:
        tmp_path: Temporary project root populated with dependency metadata files.
    """
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.2.0\n")
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires =\n    requests==2.31.0\n")
    (tmp_path / "notes.txt").write_text("not a dependency file\n")

    result = SourceDiscovery(tmp_path).discover(["."])
    files = {source.display_path: source.type for source in result.files}

    assert files == {
        "requirements-dev.txt": "text",
        "requirements.txt": "text",
        "setup.cfg": "text",
    }
