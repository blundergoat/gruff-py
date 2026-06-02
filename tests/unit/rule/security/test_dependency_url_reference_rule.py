"""Rule tests for direct URL dependency supply-chain posture findings."""

import json

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.security.dependency_url_reference_rule import DependencyUrlReferenceRule
from tests.unit.rule.security._helpers import default_ctx, make_text_unit


def test_pyproject_direct_url_dependency_fires_without_leaking_url() -> None:
    """Direct URL dependencies fire while messages/metadata omit the raw URL."""
    src = """[project]
dependencies = [
    "widget @ https://downloads.example.test/widget-1.0.0.tar.gz",
]
"""

    findings = DependencyUrlReferenceRule().analyse(
        make_text_unit(src, "pyproject.toml"), default_ctx()
    )

    assert len(findings) == 1
    finding = findings[0]
    rendered = finding.message + finding.remediation + json.dumps(finding.metadata, sort_keys=True)
    assert finding.line == 3
    assert {
        "dependencyName": "widget",
        "referenceKind": "direct-url",
        "securitySeverity": "medium",
    }.items() <= finding.metadata.items()
    assert "downloads.example.test" not in rendered
    assert "https://" not in rendered


def test_vcs_direct_url_is_left_to_git_rule() -> None:
    """Git URL dependencies are handled by the VCS-specific rule only."""
    src = """[project]
dependencies = [
    "widget @ git+https://github.com/acme/widget.git@main",
]
"""

    findings = DependencyUrlReferenceRule().analyse(
        make_text_unit(src, "pyproject.toml"), default_ctx()
    )

    assert findings == []


def test_non_dependency_toml_path_skipped() -> None:
    """Direct URLs outside dependency metadata do not trigger the rule."""
    src = 'source = "https://downloads.example.test/tool.tar.gz"\n'

    findings = DependencyUrlReferenceRule().analyse(
        make_text_unit(src, "config/tool.toml"), default_ctx()
    )

    assert findings == []


def test_url_reference_fires_via_registry_text_seam() -> None:
    """Registry dispatch routes pyproject text units to the URL rule."""
    src = """[project]
dependencies = [
    "widget @ https://downloads.example.test/widget-1.0.0.tar.gz",
]
"""

    findings = RuleRegistry.defaults().analyse(
        [make_text_unit(src, "pyproject.toml")], default_ctx()
    )

    assert "security.dependency-url-reference" in {finding.rule_id for finding in findings}
