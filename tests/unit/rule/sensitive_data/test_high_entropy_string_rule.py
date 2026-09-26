from dataclasses import replace

import pytest

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.severity import Severity
from gruffpy.rule.context import RuleContext
from gruffpy.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit

_HIGH_ENTROPY = "aB3xF7p1Q9zR4" + "yT8vW2sN5kL6" + "mP0qH1jD8wEr+/="
# Sixteen symbols cycled cannot pass 4 bits per character, so this 36-character token sits under the 4.2 default.
_CYCLED_TOKEN = ("a1b2c3d4" + "e5f6g7h8") * 2 + "a1b2"


def _context_with_thresholds(thresholds: dict[str, int | float]) -> RuleContext:
    """Return the default context with this rule's thresholds replaced.

    Args:
        thresholds: The ``minLength`` and ``entropy`` values to configure.

    Returns:
        Context whose high-entropy-string settings carry the given thresholds.
    """
    context = default_ctx()
    settings = context.config.rule_settings(HighEntropyStringRule.ID)
    config = context.config.with_rule_settings(HighEntropyStringRule.ID, replace(settings, thresholds=thresholds))
    return replace(context, config=config)


def test_definition_publishes_the_ratified_family_contract() -> None:
    """Hold the contract ratified on 2026-09-02, where py had shipped low confidence at a hardcoded 20 and 4.5."""
    definition = HighEntropyStringRule().definition()

    assert (definition.default_severity, definition.confidence, definition.default_enabled) == (Severity.WARNING, Confidence.MEDIUM, True)
    assert definition.default_thresholds == {"minLength": 32, "entropy": 4.2}


@pytest.mark.parametrize(
    ("token", "lowered"),
    [
        (_HIGH_ENTROPY[:24], {"minLength": 20, "entropy": 4.2}),
        (_CYCLED_TOKEN, {"minLength": 32, "entropy": 3.5}),
    ],
    ids=["min-length", "entropy"],
)
def test_configured_threshold_is_honoured(token: str, lowered: dict[str, int | float]) -> None:
    """Keep a token silent at the default bar and report it once, when configuration lowers that bar.

    Args:
        token: Literal that one default threshold keeps out.
        lowered: Thresholds with that one bar lowered to admit the token.
    """
    unit = make_unit(f"TOKEN = {token!r}\n")

    assert HighEntropyStringRule().analyse(unit, default_ctx()) == []
    assert [finding.rule_id for finding in HighEntropyStringRule().analyse(unit, _context_with_thresholds(lowered))] == [HighEntropyStringRule.ID]


def test_high_entropy_random_string_emits():
    src = f"KEY = {_HIGH_ENTROPY!r}\n"
    findings = HighEntropyStringRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata == {"preview": "[redacted]"}


def test_high_entropy_finding_publishes_no_value_derived_statistic():
    """FAMILY-CONTRACT section 5 forbids publishing the matched value's length or entropy."""
    src = f"KEY = {_HIGH_ENTROPY!r}\n"
    findings = HighEntropyStringRule().analyse(make_unit(src), default_ctx())
    assert "entropy" not in findings[0].metadata
    assert "length" not in findings[0].metadata
    assert str(len(_HIGH_ENTROPY)) not in str(findings[0].metadata)


@pytest.mark.parametrize(
    ("token", "reports"),
    [
        ("vxezaawdsdwcvvuvryyabvkvbgdqlcqstgddkefmpdrjp", False),
        ("VXEZAAWDSDWCVVUVRYYABVKVBGDQLCQSTGDDKEFMPDRJP", False),
        ("VxEzAaWdSdWcVvUvRyYa" + "BvKvBgDqLcQsTgDdKeFmPdRjP", False),
        ("k3j9x2m7q1w8e5r4" + "t6y0u9i8o7p6a5s4" + "d3f2g1h0zb", True),
    ],
    ids=["lowercase-only", "uppercase-only", "mixed-case-letters", "lowercase-and-digits"],
)
def test_high_entropy_needs_a_letter_and_a_digit(token: str, reports: bool) -> None:
    """Hold FAMILY-CONTRACT section 12's floor: without a letter and a digit a literal is not credential-shaped.

    gruff-go, gruff-php, gruff-rs and gruff-ts pin the same literals; the reported one is assembled from parts.

    Args:
        token: The literal under test.
        reports: Whether the rule must report it.
    """
    findings = HighEntropyStringRule().analyse(make_unit(f"value = {token!r}\n"), default_ctx())

    assert (len(findings) == 1) is reports


@pytest.mark.parametrize(
    ("label", "reports"),
    [("CERTIFICATE", False), ("PUBLIC KEY", False), ("RSA PRIVATE KEY", True)],
    ids=["certificate", "public-key", "private-key"],
)
def test_high_entropy_skips_public_pem_armour(label: str, reports: bool) -> None:
    """Skip a public PEM block's base64 body, and keep scanning a private key's.

    A certificate or public key is public by construction; the same body outside armour still reports.

    Args:
        label: The PEM label wrapping the body.
        reports: Whether the body inside that armour must report.
    """
    body = "k3j9x2m7q1w8e5r4" + "t6y0u9i8o7p6a5s4" + "d3f2g1h0zb"
    source = f'block = """-----BEGIN {label}-----\n{body}\n-----END {label}-----"""\n'

    findings = HighEntropyStringRule().analyse(make_unit(source), default_ctx())

    assert (len(findings) == 1) is reports


@pytest.mark.parametrize(
    "template",
    [
        'HEADER = "-----BEGIN CERTIFICATE-----"\nSECRET = "{body}"\nFOOTER = "-----END CERTIFICATE-----"\n',
        'OUTER = "-----BEGIN CERTIFICATE-----"\nKEY = """-----BEGIN RSA PRIVATE KEY-----\n{body}\n'
        '-----END RSA PRIVATE KEY-----"""\nEND = "-----END CERTIFICATE-----"\n',
        'A = "-----BEGIN CERTIFICATE-----\\nComment: x\\n"; KEY = "{body}"; B = "-----END CERTIFICATE-----"\n',
    ],
    ids=["marker-constants", "private-key-inside-public-markers", "header-on-a-one-line-block"],
)
def test_high_entropy_reports_between_markers_that_are_not_a_block(template: str) -> None:
    """Report a secret between public markers when the text between them is code, not a PEM body.

    A block ends at the next marker and holds only base64, so marker constants and a nested private key are not one.

    Args:
        template: Source with a ``{body}`` placeholder for the secret.
    """
    body = "k3j9x2m7q1w8e5r4" + "t6y0u9i8o7p6a5s4" + "d3f2g1h0zb"

    findings = HighEntropyStringRule().analyse(make_unit(template.format(body=body)), default_ctx())

    assert len(findings) == 1


@pytest.mark.parametrize(
    "template",
    [
        'KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\\n\\n{body}\\n=AbCd\\n-----END PGP PUBLIC KEY BLOCK-----"\n',
        '"""\n * -----BEGIN CERTIFICATE-----\n * {body}\n * -----END CERTIFICATE-----\n"""\n',
    ],
    ids=["one-line-pgp-block", "docblock"],
)
def test_high_entropy_skips_public_blocks_spelled_in_code(template: str) -> None:
    """Skip a public block written on one line with its checksum, or behind docblock stars.

    Args:
        template: Source with a ``{body}`` placeholder for the block's base64 line.
    """
    body = "k3j9x2m7q1w8e5r4" + "t6y0u9i8o7p6a5s4" + "d3f2g1h0zb"

    assert HighEntropyStringRule().analyse(make_unit(template.format(body=body)), default_ctx()) == []


def test_pascal_case_identifier_skipped():
    src = "name = 'SomeReallyLongPascalCaseIdentifier'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_path_string_skipped():
    src = "PATH = '/usr/local/bin/some_random_binary_name'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_short_high_entropy_skipped():
    src = "key = 'aB3xF7p1'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_low_entropy_long_string_skipped():
    src = "x = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
    assert HighEntropyStringRule().analyse(make_unit(src), default_ctx()) == []


def test_assignment_key_and_value_are_judged_apart() -> None:
    """Keep an environment assignment quiet when neither its key nor its value is secret-shaped.

    Joined, ``AWS_DEFAULT_REGION=ap-southeast-2`` measured 33 characters at 4.62 bits per character.
    """
    src = "AWS_DEFAULT_REGION=" + "ap-southeast-2\nAPI_TOKEN=" + "short-value\n"
    assert HighEntropyStringRule().analyse(make_unit(src, ".env.example"), default_ctx()) == []


def test_padded_base64_secret_still_emits() -> None:
    """Report a padded base64 secret whose padding the candidate boundary now trims."""
    padded = "c2VjcmV0LXZhbHVl" + "LXdpdGgtcGFkZGlu" + "Zy0xMjM0NTY3OA=="
    findings = HighEntropyStringRule().analyse(make_unit(f"SESSION_KEY={padded}\n", ".env"), default_ctx())
    assert len(findings) == 1
