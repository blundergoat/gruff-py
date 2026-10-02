"""Check which private-key source shapes produce warnings for developers.

The rule runs on authored source strings, including incomplete keys and the explicit placeholder example.
These checks keep warning previews redacted while preventing short opaque material from being dismissed.
"""

import pytest

from gruffpy.rule.sensitive_data.private_key_rule import PrivateKeyRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_rsa_header_emits():
    """A developer scanning a complete RSA-shaped block receives a private-key warning."""
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = f"{header}\nMIIE{('A' * 120)}\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_openssh_header_emits():
    """A developer scanning an OpenSSH-shaped block receives the same private-key warning."""
    header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    footer = "-----END OPENSSH " + "PRIVATE KEY-----"
    source_text = f"{header}\nb3BlbnNzaC1rZXk={('A' * 120)}\n{footer}\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_ec_header_emits():
    """An incomplete EC-shaped block still warns when a developer scans the source."""
    header = "-----BEGIN EC " + "PRIVATE KEY-----"
    source_text = f"{header}\nMHcCAQ...\n"
    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())
    assert len(findings) == 1


def test_public_key_not_flagged():
    """Publishing a public key does not produce a private-key warning."""
    source_text = "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----\n"
    assert PrivateKeyRule().analyse(make_unit(source_text), default_ctx()) == []


def test_placeholder_private_key_block_skipped():
    """A complete example block containing only placeholder stays quiet."""
    header = "-----BEGIN " + "PRIVATE KEY-----"
    footer = "-----END " + "PRIVATE KEY-----"
    source_text = f"{header}\nplaceholder\n{footer}\n"

    assert PrivateKeyRule().analyse(make_unit(source_text), default_ctx()) == []


def test_short_opaque_private_key_body_emits():
    """Short opaque key material still warns, and its report exposes only a category marker."""
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = f"{header}\nMIIEowIBAAKCAQEA\n{footer}\n"

    findings = PrivateKeyRule().analyse(make_unit(source_text), default_ctx())

    assert len(findings) == 1
    assert findings[0].line == 1
    assert findings[0].metadata == {"preview": "[redacted:private-key]"}


def test_isolated_private_key_header_emits():
    """A bare private-key header warns even when the developer has omitted the body."""
    header = "-----BEGIN " + "PRIVATE KEY-----"

    assert len(PrivateKeyRule().analyse(make_unit(header), default_ctx())) == 1


def test_escaped_truncated_private_key_body_emits():
    """Escaped line breaks and an unfinished string value do not hide a private-key header."""
    header = "-----BEGIN EC " + "PRIVATE KEY-----"
    source_text = f'private_key = "{header}\\nMIIEowIBAAKCAQEA"'

    assert len(PrivateKeyRule().analyse(make_unit(source_text), default_ctx())) == 1


def test_placeholder_word_inside_opaque_key_body_does_not_silence_it():
    """An opaque body containing the word placeholder still warns when the developer scans it."""
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
    """A malformed placeholder example retains each header's warning.

    Args:
        source_template: Nonempty authored example whose markers are filled in before the developer's scan.
        expected_warnings: Positive count of headers the malformed example must leave reportable.
    """
    header = "-----BEGIN " + "PRIVATE KEY-----"
    footer = "-----END " + "PRIVATE KEY-----"
    rsa_footer = "-----END RSA " + "PRIVATE KEY-----"
    source_text = source_template.format(header=header, footer=footer, rsa_footer=rsa_footer)

    assert len(PrivateKeyRule().analyse(make_unit(source_text), default_ctx())) == expected_warnings
