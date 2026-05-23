"""Security taxonomy helpers for rule and finding metadata."""

from typing import Any

_RULE_SECURITY_METADATA: dict[str, dict[str, Any]] = {
    "security.sql-concatenation": {
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "securitySeverity": "high",
    },
    "security.disabled-ssl-verification": {
        "cwe": ["CWE-295"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "securitySeverity": "high",
    },
    "security.unsafe-yaml-load": {
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021-Software and Data Integrity Failures"],
        "securitySeverity": "high",
    },
    "security.weak-crypto": {
        "cwe": ["CWE-327", "CWE-916"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "securitySeverity": "medium",
    },
    "security.insecure-tls-protocol": {
        "cwe": ["CWE-326", "CWE-327"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "securitySeverity": "high",
    },
    "security.flask-debug-enabled": {
        "cwe": ["CWE-489", "CWE-215"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "securitySeverity": "high",
    },
    "security.xxe": {
        "cwe": ["CWE-611", "CWE-776"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "securitySeverity": "high",
    },
    "security.jinja2-autoescape-off": {
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021-Injection"],
        "securitySeverity": "high",
    },
    "security.django-mark-safe": {
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021-Injection"],
        "securitySeverity": "medium",
    },
    "security.django-raw-sql": {
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "securitySeverity": "high",
    },
    "security.paramiko-no-host-key-check": {
        "cwe": ["CWE-295", "CWE-322"],
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "securitySeverity": "high",
    },
    "security.hardcoded-bind-all-interfaces": {
        "cwe": ["CWE-668"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "securitySeverity": "medium",
    },
    "security.insecure-temp-file": {
        "cwe": ["CWE-377", "CWE-379"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "securitySeverity": "medium",
    },
    "security.cors-wildcard-with-credentials": {
        "cwe": ["CWE-942", "CWE-346"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "securitySeverity": "high",
    },
    "security.hardcoded-framework-secret-key": {
        "cwe": ["CWE-798", "CWE-321"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "securitySeverity": "high",
    },
    "security.ssrf": {
        "cwe": ["CWE-918"],
        "owasp": ["A10:2021-Server-Side Request Forgery"],
        "securitySeverity": "high",
    },
    "security.path-traversal": {
        "cwe": ["CWE-22"],
        "owasp": ["A01:2021-Broken Access Control"],
        "securitySeverity": "high",
    },
}


def rule_security_metadata(rule_id: str) -> dict[str, Any]:
    """Return optional security taxonomy for a built-in rule.

    Args:
        rule_id: Rule identifier to look up.

    Returns:
        Copy of the rule's taxonomy metadata, or an empty mapping.
    """
    return dict(_RULE_SECURITY_METADATA.get(rule_id, {}))


def finding_security_metadata(
    rule_id: str,
    *,
    source_label: str = "",
    sink_label: str = "",
) -> dict[str, Any]:
    """Return JSON-ready security metadata for an individual finding.

    Args:
        rule_id: Rule identifier to look up.
        source_label: Optional source taxonomy label for the finding.
        sink_label: Optional sink taxonomy label for the finding.

    Returns:
        Security taxonomy plus optional source and sink labels.
    """
    metadata = rule_security_metadata(rule_id)
    if source_label:
        metadata["sourceLabel"] = source_label
    if sink_label:
        metadata["sinkLabel"] = sink_label
    return metadata
