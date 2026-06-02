"""Rule tests for Git dependency supply-chain posture findings."""

import json

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.security.dependency_git_reference_rule import DependencyGitReferenceRule
from tests.unit.rule.security._helpers import default_ctx, make_text_unit, make_unit


def test_requirement_vcs_dependency_fires_without_leaking_repository_url() -> None:
    """Git dependencies fire while messages/metadata omit the repository URL."""
    src = "-e git+https://github.com/acme/widget.git@main#egg=widget\n"

    findings = DependencyGitReferenceRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )

    assert len(findings) == 1
    finding = findings[0]
    rendered = finding.message + finding.remediation + json.dumps(finding.metadata, sort_keys=True)
    assert finding.line == 1
    assert {
        "dependencyName": "widget",
        "referenceKind": "vcs-git",
    }.items() <= finding.metadata.items()
    assert "github.com" not in rendered
    assert "git+https://" not in rendered


def test_pyproject_vcs_dependency_fires() -> None:
    """PEP 621 direct references using git+ schemes trigger the Git rule."""
    src = """[project]
dependencies = [
    "widget @ git+ssh://git.example.test/acme/widget.git@v1",
]
"""

    findings = DependencyGitReferenceRule().analyse(
        make_text_unit(src, "pyproject.toml"), default_ctx()
    )

    assert len(findings) == 1
    assert findings[0].metadata["dependencyName"] == "widget"


def test_non_git_url_dependency_skipped() -> None:
    """Plain HTTP(S) direct references are left to the direct-URL rule."""
    src = "widget @ https://downloads.example.test/widget-1.0.0.tar.gz\n"

    findings = DependencyGitReferenceRule().analyse(
        make_text_unit(src, "requirements.txt"), default_ctx()
    )

    assert findings == []


def test_setup_py_git_dependency_fires_via_registry_python_seam() -> None:
    """Dependency text rules also inspect parsed setup.py metadata."""
    src = """from setuptools import setup

setup(install_requires=[
    "widget @ git+https://github.com/acme/widget.git@main",
])
"""

    findings = [
        finding
        for finding in RuleRegistry.defaults().analyse(
            [make_unit(src, "setup.py")],
            default_ctx(),
        )
        if finding.rule_id == "security.dependency-git-reference"
    ]

    assert len(findings) == 1
    assert findings[0].line == 4
    assert findings[0].metadata["dependencyName"] == "widget"
