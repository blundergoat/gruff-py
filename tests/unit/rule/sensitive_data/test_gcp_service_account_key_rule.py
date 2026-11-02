"""Exercise Google Cloud service-account key findings in JSON-shaped input.

The suite covers registry routing, real and placeholder key material, source locations, and the
fixed preview users receive without private-key or key-ID fragments.
"""

from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.sensitive_data.gcp_service_account_key_rule import GcpServiceAccountKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_PRIVATE_KEY_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
_PRIVATE_KEY_FOOTER = "-----END " + "PRIVATE KEY-----"
_PRIVATE_KEY_BODY = "MIIEv" + ("A" * 120)
_PRIVATE_KEY_VALUE = f"{_PRIVATE_KEY_HEADER}\\n{_PRIVATE_KEY_BODY}\\n{_PRIVATE_KEY_FOOTER}\\n"
_PRIVATE_KEY_ID = "abc123" + "def456" + "abc123" + "def456"


def test_gcp_service_account_key_emits_with_redacted_preview():
    """Report one finding on line 2 whose metadata holds only the category, fixed preview and provider, with no key material in its text."""
    src = _service_account_source(_PRIVATE_KEY_VALUE)

    findings = GcpServiceAccountKeyRule().analyse(make_unit(src, "service-account.json"), default_ctx())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "sensitive-data.gcp-service-account-key"
    assert finding.line == 2
    assert finding.metadata == {
        "category": "service-account-key",
        "preview": "[redacted:gcp-service-account]",
        "provider": "gcp",
    }
    _assert_gcp_raw_values_redacted(finding.message, str(finding.metadata))


def test_gcp_service_account_key_routes_through_default_registry():
    """Report the GCP service-account rule through the default registry for a service-account JSON file."""
    findings = RuleRegistry.defaults().analyse(
        [make_unit(_service_account_source(_PRIVATE_KEY_VALUE), "service-account.json")],
        default_ctx(),
    )
    rule_ids = {finding.rule_id for finding in findings}

    assert "sensitive-data.gcp-service-account-key" in rule_ids


def test_service_account_marker_without_private_key_skipped():
    """Report nothing for a service-account JSON file without a private key."""
    src = '{"type": "service_account", "client_email": "fixture@' + 'example.test"}\n'

    assert GcpServiceAccountKeyRule().analyse(make_unit(src, "service-account.json"), default_ctx()) == []


def test_private_key_without_service_account_marker_skipped_by_gcp_rule():
    """Report nothing from this rule for a private key in JSON that lacks the service-account type marker."""
    src = '{"private_key": "' + _PRIVATE_KEY_VALUE + '"}\n'

    assert GcpServiceAccountKeyRule().analyse(make_unit(src, "key.json"), default_ctx()) == []


def test_placeholder_service_account_key_skipped():
    """Report nothing for a service-account key whose private-key body is a placeholder."""
    src = _service_account_source(f"{_PRIVATE_KEY_HEADER}\\nplaceholder\\n{_PRIVATE_KEY_FOOTER}\\n")

    assert GcpServiceAccountKeyRule().analyse(make_unit(src, "service-account.json"), default_ctx()) == []


def _service_account_source(private_key: str) -> str:
    """Return service-account JSON text holding the fixed key id and the given private key.

    Args:
        private_key: Value written into the ``private_key`` field.

    Returns:
        JSON text with the service-account type, key id and private key fields.
    """
    return f'{{\n  "type": "service_account",\n  "private_key_id": "{_PRIVATE_KEY_ID}",\n  "private_key": "{private_key}"\n}}\n'


def _assert_gcp_raw_values_redacted(*rendered_values: str) -> None:
    """Fail when any rendered value contains the fixture's private key or key id.

    Args:
        rendered_values: Finding text to check, such as a message or stringified metadata.

    Raises:
        AssertionError: A rendered value contains the raw private key or key id.
    """
    for raw_value in (_PRIVATE_KEY_VALUE, _PRIVATE_KEY_ID):
        assert all(raw_value not in rendered for rendered in rendered_values)
