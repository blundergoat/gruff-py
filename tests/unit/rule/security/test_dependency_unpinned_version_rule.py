"""Rule tests for floating dependency-version supply-chain findings."""

from gruffpy.rule.security.dependency_unpinned_version_rule import DependencyUnpinnedVersionRule
from tests.unit.rule.security._helpers import default_ctx, make_text_unit


def test_requirements_unpinned_and_wildcard_versions_fire() -> None:
    """Missing, range, and wildcard constraints are reported as floating versions."""
    src = """requests>=2.31
click
urllib3==2.*
pytest==8.2.0
"""

    findings = DependencyUnpinnedVersionRule().analyse(
        make_text_unit(src, "requirements-dev.txt"),
        default_ctx(),
    )

    assert [(finding.line, finding.metadata["dependencyName"]) for finding in findings] == [
        (1, "requests"),
        (2, "click"),
        (3, "urllib3"),
    ]
    assert {finding.metadata["constraintKind"] for finding in findings} == {
        "range-or-compatible",
        "missing",
        "wildcard",
    }


def test_pyproject_exact_pins_are_skipped() -> None:
    """Exact non-wildcard PEP 621 dependencies satisfy the rule."""
    src = """[project]
dependencies = [
    "click==8.1.7",
    "pytest===8.2.0",
]
"""

    findings = DependencyUnpinnedVersionRule().analyse(
        make_text_unit(src, "pyproject.toml"),
        default_ctx(),
    )

    assert findings == []


def test_direct_references_are_left_to_reference_rules() -> None:
    """URL, Git, and local-path references do not also emit unpinned findings."""
    src = """widget @ https://downloads.example.test/widget-1.0.0.tar.gz
-e ../local-widget
git+https://github.com/acme/widget.git@main#egg=widget
"""

    findings = DependencyUnpinnedVersionRule().analyse(
        make_text_unit(src, "requirements.txt"),
        default_ctx(),
    )

    assert findings == []


def test_setup_cfg_dependencies_are_scanned() -> None:
    """setup.cfg install and extra requirements are dependency metadata too."""
    src = """[options]
install_requires =
    requests>=2.31
[options.extras_require]
dev =
    pytest
"""

    findings = DependencyUnpinnedVersionRule().analyse(
        make_text_unit(src, "setup.cfg"),
        default_ctx(),
    )

    assert [(finding.line, finding.metadata["dependencyName"]) for finding in findings] == [
        (3, "requests"),
        (6, "pytest"),
    ]
