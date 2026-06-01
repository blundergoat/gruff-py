"""Rule tests for local path dependency supply-chain posture findings."""

from gruffpy.rule.security.dependency_git_reference_rule import DependencyGitReferenceRule
from gruffpy.rule.security.dependency_local_path_rule import DependencyLocalPathRule
from tests.unit.rule.security._helpers import default_ctx, make_text_unit


def test_requirement_local_path_dependencies_fire_without_leaking_paths() -> None:
    """Local path dependencies fire while messages/remediation omit the raw paths."""
    src = """-e ../shared-widget
./vendor/widget
widget @ file:///opt/internal/widget
"""

    findings = DependencyLocalPathRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )

    assert [(finding.line, finding.metadata["referenceKind"]) for finding in findings] == [
        (1, "local-path"),
        (2, "local-path"),
        (3, "file-url"),
    ]
    assert findings[2].metadata["dependencyName"] == "widget"
    rendered = "\n".join(finding.message + finding.remediation for finding in findings)
    assert "../shared-widget" not in rendered
    assert "./vendor/widget" not in rendered
    assert "/opt/internal/widget" not in rendered


def test_ssh_git_reference_is_not_flagged_as_local_path() -> None:
    """An scp-style SSH Git dependency is a VCS ref; only the git-reference rule fires."""
    src = "git@github.com:org/repo.git#egg=widget\n"

    local_findings = DependencyLocalPathRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )
    git_findings = DependencyGitReferenceRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )

    assert local_findings == []
    assert len(git_findings) == 1


def test_pinned_named_requirement_skipped() -> None:
    """A normal exact-pinned package requirement is not a local path reference."""
    src = "requests==2.31.0\n"

    findings = DependencyLocalPathRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )

    assert findings == []


def test_pyproject_file_url_dependency_fires() -> None:
    """PEP 621 file URL dependencies trigger the local-path rule."""
    src = """[project]
dependencies = [
    "widget @ file:///opt/internal/widget",
]
"""

    findings = DependencyLocalPathRule().analyse(
        make_text_unit(src, "pyproject.toml"), default_ctx()
    )

    assert len(findings) == 1
    assert findings[0].metadata["dependencyName"] == "widget"
