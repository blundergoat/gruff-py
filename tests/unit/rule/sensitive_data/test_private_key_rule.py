"""Check which private-key source shapes produce warnings for developers.

The rule runs on authored source strings, including incomplete keys and the explicit placeholder example.
These checks keep warning previews redacted while preventing short opaque material from being dismissed.
"""

import pytest

from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_rsa_header_emits():
    """A developer scanning a complete RSA-shaped block receives a private-key warning.

    Returns:
        None after verifying that the RSA block produces one finding.
    """
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = f"{header}\nMIIE{('A' * 120)}\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_openssh_header_emits():
    """An OpenSSH-shaped block produces one private-key finding.

    Returns:
        None after verifying that the OpenSSH block produces one finding.
    """
    header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    footer = "-----END OPENSSH " + "PRIVATE KEY-----"
    source_text = f"{header}\nb3BlbnNzaC1rZXk={('A' * 120)}\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_ec_header_emits():
    """An incomplete EC-shaped block still warns when a developer scans the source.

    Returns:
        None after verifying that the incomplete EC block produces one finding.
    """
    header = "-----BEGIN EC " + "PRIVATE KEY-----"
    source_text = f"{header}\nMHcCAQ...\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_public_key_not_flagged():
    """A public-key block produces no private-key findings.

    Returns:
        None after verifying that the public key produces no private-key findings.
    """
    source_text = "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n"
    assert PrivateKeyRule().analyse(make_unit(source_text), default_ctx()) == []


def test_placeholder_private_key_block_skipped():
    """A complete example block containing only placeholder stays quiet.

    Returns:
        None after verifying that the complete placeholder block produces no findings.
    """
    header = "-----BEGIN " + "PRIVATE KEY-----"
    footer = "-----END " + "PRIVATE KEY-----"
    source_text = f"{header}\nplaceholder\n{footer}\n"

    assert PrivateKeyRule().analyse(make_unit(source_text), default_ctx()) == []


def test_short_opaque_private_key_body_emits():
    """Short opaque key material still warns, with only a category marker in the finding metadata.

    Returns:
        None after verifying the finding count, source line and redacted metadata.
    """
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = f"{header}\nMIIEowIBAAKCAQEA\n{footer}\n"

    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())

    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].metadata == {"preview": "[redacted:private-key]"}


def test_isolated_private_key_header_emits():
    """A bare private-key header warns even when the developer has omitted the body.

    Returns:
        None after verifying that the bare header produces one finding.
    """
    header = "-----BEGIN " + "PRIVATE KEY-----"

    assert len(PrivateKeyRule().analyse(make_unit(header), default_ctx())) == 1


def test_escaped_truncated_private_key_body_emits():
    """Escaped line breaks and a truncated key body do not hide a private-key header.

    Returns:
        None after verifying that the escaped, truncated key produces one finding.
    """
    header = "-----BEGIN EC " + "PRIVATE KEY-----"
    source_text = f'private_key = "{header}\\nMIIEowIBAAKCAQEA"'

    assert len(PrivateKeyRule().analyse(make_unit(source_text), default_ctx())) == 1


def test_placeholder_word_inside_opaque_key_body_does_not_silence_it():
    """An opaque body containing the word placeholder still warns when the developer scans it.

    Returns:
        None after verifying that the opaque body produces one finding.
    """
    header = "-----BEGIN " + "PRIVATE KEY-----"
    footer = "-----END " + "PRIVATE KEY-----"
    source_text = f"{header}\nMIIEplaceholderAQEA\n{footer}\n"

    assert len(PrivateKeyRule().analyse(make_unit(source_text), default_ctx())) == 1


@pytest.mark.parametrize(
    ("source_template", "expected_warnings"),
    [
        ("{header}\nplaceholder\n{rsa_footer}", 1),
        ("{header}\n{header}\nplaceholder\n{footer}", 2),
        ("{header}\nplaceholder", 1),
    ],
    ids=["mismatched-footer", "nested-bare-header", "unfinished-block"],
)
def test_placeholder_requires_matching_unbroken_private_key_armour(source_template: str, expected_warnings: int):
    """Verify warning counts for mismatched, nested, and unfinished placeholder blocks.

    Args:
        source_template: Fixture template filled with private-key header and footer text before the test runs the rule.
        expected_warnings: Positive finding count expected for the malformed example.

    Returns:
        None after verifying the malformed example's warning count.
    """
    header = "-----BEGIN " + "PRIVATE KEY-----"
    footer = "-----END " + "PRIVATE KEY-----"
    rsa_footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = source_template.format(header=header, footer=footer, rsa_footer=rsa_footer)

    assert len(PrivateKeyRule().analyse(make_unit(source_text), default_ctx())) == expected_warnings


@pytest.mark.parametrize(
    ("source_template", "expected_warnings"),
    [
        ("_SK_START = b'{header}'\n_SK_END = b'{footer}'\n", 0),
        ("_SK_START = b'{header}'\nKEY_DATA = b'MIIEowIBAAKCAQEA'\n_SK_END = b'{footer}'\n", 1),
        ("_SK_START = b'{header}'\n_SK_END = b'{rsa_footer}'\n", 1),
        ("_SK_START = b'{header}'\n", 1),
    ],
    ids=["parser-markers", "opaque-body-between-markers", "mismatched-marker-labels", "unmatched-marker"],
)
def test_parser_marker_pairs_require_empty_matching_assignments(source_template: str, expected_warnings: int):
    """Keep parser delimiters quiet without hiding opaque or unmatched key material.

    Args:
        source_template: Template filled with key delimiters to test matching markers, intervening data, and mismatched or missing footers.
        expected_warnings: Zero only for the matching marker-only pair; other controls retain one warning.

    Returns:
        None after verifying the warning count and redacted finding metadata.
    """
    header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    footer = "-----END OPENSSH " + "PRIVATE KEY-----"
    rsa_footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = source_template.format(header=header, footer=footer, rsa_footer=rsa_footer)

    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())

    assert len(findings) == expected_warnings
    assert all(finding.metadata == {"preview": "[redacted:private-key]"} for finding in findings)
