"""Regression tests for the reviewer-verification rule posture."""

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.rule.registry import RuleRegistry

Posture = tuple[bool, str, str]


_DOCS_MISSING_POSTURE: dict[str, Posture] = {
    "docs.missing-class-docstring": (True, "warning", "high"),
    "docs.missing-function-docstring": (True, "warning", "high"),
    "docs.missing-module-docstring": (True, "advisory", "medium"),
    "docs.missing-param-doc": (True, "advisory", "medium"),
    "docs.missing-raises-doc": (True, "advisory", "low"),
    "docs.missing-readme": (True, "advisory", "medium"),
    "docs.missing-return-doc": (True, "advisory", "medium"),
}

_SECURITY_POSTURE: dict[str, Posture] = {
    "security.cors-wildcard-with-credentials": (True, "error", "high"),
    "security.dangerous-function-call": (True, "error", "high"),
    "security.dependency-git-reference": (True, "warning", "high"),
    "security.dependency-local-path": (True, "warning", "high"),
    "security.dependency-url-reference": (True, "warning", "high"),
    "security.disabled-ssl-verification": (True, "error", "high"),
    "security.django-mark-safe": (True, "warning", "medium"),
    "security.django-raw-sql": (True, "warning", "high"),
    "security.error-suppression": (True, "advisory", "medium"),
    "security.extract-compact-user-input": (True, "warning", "medium"),
    "security.flask-debug-enabled": (True, "error", "high"),
    "security.github-actions-broad-permissions": (True, "warning", "high"),
    "security.github-actions-pull-request-target": (True, "error", "high"),
    "security.github-actions-remote-shell": (True, "warning", "high"),
    "security.github-actions-secrets-in-pr": (True, "warning", "medium"),
    "security.github-actions-unpinned-action": (True, "warning", "high"),
    "security.hardcoded-bind-all-interfaces": (True, "warning", "medium"),
    "security.hardcoded-framework-secret-key": (True, "error", "high"),
    "security.header-injection": (True, "warning", "medium"),
    "security.insecure-random": (True, "warning", "medium"),
    "security.insecure-temp-file": (True, "warning", "medium"),
    "security.insecure-tls-protocol": (True, "error", "high"),
    "security.jinja2-autoescape-off": (True, "error", "high"),
    "security.paramiko-no-host-key-check": (True, "error", "high"),
    "security.path-traversal": (True, "error", "high"),
    "security.shell-injection": (True, "error", "high"),
    "security.silent-except": (True, "advisory", "high"),
    "security.sql-concatenation": (True, "warning", "medium"),
    "security.ssrf": (True, "error", "high"),
    "security.unsafe-pickle": (True, "error", "high"),
    "security.unsafe-yaml-load": (True, "error", "high"),
    "security.variable-import": (True, "warning", "medium"),
    "security.weak-crypto": (True, "warning", "high"),
    "security.xxe": (True, "error", "high"),
}

_SENSITIVE_DATA_POSTURE: dict[str, Posture] = {
    "sensitive-data.api-key-pattern": (True, "warning", "high"),
    "sensitive-data.aws-access-key": (True, "error", "high"),
    "sensitive-data.database-url-password": (True, "error", "high"),
    "sensitive-data.gcp-service-account-key": (True, "error", "high"),
    "sensitive-data.hardcoded-env-value": (True, "warning", "medium"),
    "sensitive-data.high-entropy-string": (True, "warning", "low"),
    "sensitive-data.jwt-token": (True, "warning", "high"),
    "sensitive-data.phi-pattern": (True, "error", "medium"),
    "sensitive-data.pii-test-fixture": (True, "warning", "medium"),
    "sensitive-data.private-key": (True, "error", "high"),
    "sensitive-data.url-credentials": (True, "error", "high"),
}


@pytest.mark.parametrize(
    ("expected", "prefix"),
    (
        (_DOCS_MISSING_POSTURE, "docs.missing"),
        (_SECURITY_POSTURE, "security."),
        (_SENSITIVE_DATA_POSTURE, "sensitive-data."),
    ),
    ids=("docs.missing-*", "security.*", "sensitive-data.*"),
)
def test_reviewer_verification_families_keep_default_posture(
    expected: dict[str, Posture], prefix: str
) -> None:
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)

    actual = {
        definition.id: (
            config.rule_settings(definition.id).enabled,
            definition.default_severity.value,
            definition.confidence.value,
        )
        for rule in registry.all()
        if (definition := rule.definition()).id.startswith(prefix)
    }

    assert actual == expected
