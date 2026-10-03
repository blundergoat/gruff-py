"""Check which source values appear in the user's entropy warnings.

Public-shape controls must stay quiet while related opaque values retain their findings.
Threshold and redaction checks preserve the report contract when users tune the rule.
"""

from dataclasses import replace
from pathlib import Path

import pytest

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.sensitive_data.high_entropy_string_rule import HighEntropyStringRule
from gruffpy.source.source_file import SourceFile
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


def test_documented_samples_are_not_reported() -> None:
    """Skip AWS's example key and the jwt.io sample token, and keep reporting a live-shaped key and a longer token."""
    from gruffpy.rule.sensitive_data.aws_access_key_rule import AwsAccessKeyRule
    from gruffpy.rule.sensitive_data.jwt_token_rule import JwtTokenRule

    example = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    live = "AKIA" + "Q7R2M8N4" + "P6T9V1X3"
    jwt = ".".join(
        [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
    )
    source = f"EXAMPLE_KEY = {example!r}\nLIVE_KEY = {live!r}\nSAMPLE = {jwt!r}\nLONGER = {jwt + 'x'!r}\n"
    unit = make_unit(source)

    assert [finding.line for finding in AwsAccessKeyRule().analyse(unit, default_ctx())] == [2]
    assert [finding.line for finding in JwtTokenRule().analyse(unit, default_ctx())] == [4]


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


_SHARED_ENTROPY_POLICY_CASES = (
    ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", False),
    ("1023456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z00123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", True),
    ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", False),
    ("http://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://reader:@github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com:443/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com.invalid/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e?mode=debug", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e#details", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e/details", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e0", True),
    ("https://github.com/python/cpython/commit/6E8DCDAAA49D4313BF9FAB9F9923CA5828FBB10E", True),
    ("https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10eq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("https://github.com/-python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com/python-/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com/python/.cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("https://github.com/python//commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("/hc/en-au/categories/360002157933-Schedule", False),
    ("https://support.halaxy.com/hc/en-au/articles/6033481017999-Customise-your-reminder-templates", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==", True),
    ("BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", True),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("/hc/en-au/categories/360002157933-Scheduleq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("public/hc/en-au/categories/360002157933-Schedule", True),
    ("/hc/en-au/categories/360002157933-Schedule-Ab", True),
    ("/hc/en-au/categories/360002157933-ScHeDuLe", True),
    ("/hc/en-au/categories/360002157933-Schedule-AlphabeticRepresentationReference", True),
    ("/hc/en-au/categories/360002157933-Schedule-123", True),
    ("/hc/en-au/categories/3600021579337-Schedule", True),
    ("github.com/aws/aws-sdk-go-v2/feature/ec2/imds", False),
    ("../../examples/tutorial_derive/03_02_option_mult.md", False),
    ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", False),
    ("github.com/aws/aws-sdk-go-v2/feature/ec2/imdsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("../../manuals/tutorial_derive/03_02_option_mult.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("../../../manuals/tutorial_derive/03_02_option_mult.md/DeveloperGuide", True),
    ("github.com/aws/aws-sdk-go-v2/feature/ec23/imds", True),
    ("bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890a", True),
    ("https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-group", False),
    ("prefix 'https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false' suffix", True),
    ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false", False),
    ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", False),
    ("ComposerAutoloaderInit386a05f6676643b8b2eb49288e20d079", True),
    ("Cryptography_HAS_TLSv1_3_HS_FUNCTIONS", False),
    ("chacha20poly1305_bad_tag_second_chunk_full", False),
    ("Cryptography_STACK_OF_X509_OBJECT *X509_STORE_get0_objects(X509_STORE *);", False),
    ("int sk_X509_OBJECT_num(Cryptography_STACK_OF_X509_OBJECT *);", False),
    ("Cryptography_HAS_TLSv1_3_FUNCTIONS", False),
    ("cryptography-manylinux2014_aarch64", False),
    ("aes256gcm_bad_tag_empty_final_chunk", False),
    ("static const long Cryptography_HAS_TLSv1_3_HS_FUNCTIONS = 0;", False),
    ("chacha20poly1305_bad_tag_first_chunk", False),
    ("soljson-v0.8.21+commit.d9974bed.js", False),
    ("./node_modules/core-js/internals/v8-prototype-define-bug.js", False),
    ("SNYK-JS-EXPRESSFILEUPLOAD-473997", False),
    ("1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com", False),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", True),
    ("public_metadata_q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("public_metadata_alphaq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("public_metadata_q7W9e2R4t6Y8u1I3o5P0_a9S7d5F3g1H8j6K4l2Z0", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.comq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", False),
    ("abcdefghijklmnopqrstuvwxyz0123456789-_", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", False),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", False),
    ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789", False),
    ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", False),
    ("Com.Example2.Services.Authentication.TokenProvider", False),
    ("docs/decisions/ADR-020-DeferCorpusScoringParity2.md", False),
    ("deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", False),
    ("Qwen/Qwen2.5-Coder-32B-Instruct-AWQ", False),
    (".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", False),
    ("/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", False),
    (".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.mdq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("..goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md", True),
    ("//repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md", True),
    ("Automattic/i18n-check-webpack-plugin", False),
    ("var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.json", False),
    ("var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsv", False),
    ("/hc/en-au/sections/360005188513-Appointments", False),
    ("/hc/en-au/sections/360005149694-Communication-Report", False),
    ("PH_ObservationInterpretation_HL7_V3", False),
    ("PHVS_ObservationInterpretation_HL7_V3", False),
    ("Automattic/i18n-check-webpack-pluginq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    (
        "var/quality/full-corpus-20260710T2328Z/primock57-day2-consultation09-i-cant-move-my-left-arm/live-history.jsonq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0",
        True,
    ),
    ("var/quality/0.5.0-harness-20260717T011802Z/t02.9-holdout-registration.tsvq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("/hc/en-au/sections/360005188513-Appointmentsq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("/hc/en-au/sections/360005149694-Communication-Reportq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("PH_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("PHVS_ObservationInterpretation_HL7_V3q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/sections/360005188513-Appointments", True),
    ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0PH_ObservationInterpretation_HL7_V3", True),
)
_SHARED_ENTROPY_POLICY_IDS = (
    "review3-24-uuid-alphabet",
    "uuid-alphabet-permutation",
    "uuid-alphabet-opaque-prefix",
    "uuid-alphabet-opaque-tail",
    "review3-18-commit-url",
    "commit-http",
    "commit-credentials",
    "commit-port",
    "commit-host-suffix",
    "commit-query",
    "commit-fragment",
    "commit-path-tail",
    "commit-short-revision",
    "commit-long-revision",
    "commit-uppercase-revision",
    "commit-opaque-tail",
    "commit-owner-leading-hyphen",
    "commit-owner-trailing-hyphen",
    "commit-repo-leading-dot",
    "commit-empty-repo",
    "recaptchaSiteKey",
    "review2-4-category",
    "review2-34-article",
    "review2-45-base64-decoder",
    "decoder-extra-padding",
    "decoder-permutation",
    "decoder-opaque-prefix",
    "decoder-opaque-tail",
    "category-opaque-tail",
    "category-unapproved-prefix",
    "category-short-word",
    "category-mixed-case",
    "category-overlong-word",
    "category-numeric-label",
    "category-long-id",
    "review-1-ec2",
    "review-43-parent-path",
    "review-46-hashids-alphabet",
    "ec2-opaque-tail",
    "parent-path-opaque-tail",
    "hashids-alphabet-opaque-tail",
    "three-parent-path",
    "unknown-ec2-code",
    "unknown-alphabet-permutation",
    "review-5-complete-help-url",
    "embedded-public-url",
    "review-34-complete-sqs-url",
    "case-50",
    "case-149",
    "case-243",
    "case-244",
    "case-245",
    "case-247",
    "case-249",
    "case-250",
    "case-252",
    "case-254",
    "case-256",
    "case-434",
    "case-435",
    "case-443",
    "case-444",
    "opaque",
    "alphabet-tail",
    "opaque-prefix-alphabet",
    "structured-tail",
    "misleading-word-prefix",
    "split-opaque-tail",
    "path",
    "ruleId",
    "clientId",
    "public-format-tail",
    "alphabet-0",
    "alphabet-1",
    "alphabet-2",
    "alphabet-3",
    "alphabet-4",
    "alphabet-5",
    "alphabet-6",
    "alphabet-7",
    "legacy-0",
    "legacy-1",
    "legacy-2",
    "legacy-3",
    "hidden-path",
    "rooted-path",
    "hidden-path-opaque-tail",
    "rooted-path-opaque-tail",
    "repeated-leading-dot",
    "repeated-leading-slash",
    "i18n",
    "timestamp-minute",
    "timestamp-second",
    "help-appointments",
    "help-report",
    "clinical-code",
    "clinical-value-set",
    "i18n-opaque-tail",
    "timestamp-minute-opaque-tail",
    "timestamp-second-opaque-tail",
    "help-appointments-opaque-tail",
    "help-report-opaque-tail",
    "clinical-code-opaque-tail",
    "clinical-value-set-opaque-tail",
    "help-appointments-opaque-prefix",
    "clinical-code-opaque-prefix",
)


@pytest.mark.parametrize(("candidate", "should_report"), _SHARED_ENTROPY_POLICY_CASES, ids=_SHARED_ENTROPY_POLICY_IDS)
def test_shared_entropy_policy(candidate: str, should_report: bool) -> None:
    """Reproduce F01 public shapes and authored opaque controls on the actual detector.

    Args:
        candidate: Frozen benign source projection or inert authored mutation.
        should_report: Whether the approved policy requires a warning.
    """
    findings = HighEntropyStringRule().analyse(make_unit(f"value = {candidate!r}\n"), default_ctx())
    assert len(findings) == int(should_report)


@pytest.mark.parametrize(
    ("url", "should_report"),
    [
        ("https://support.halaxy.com/hc/en-au/articles/6033481017999-Customise-your-reminder-templates", False),
        ("https://support.halaxy.com/hc/en-au/articles/60334810179-Customise-your-reminder-templates", True),
        ("https://support.halaxy.com/hc/en-au/articles/60334810179990-Customise-your-reminder-templates", True),
        ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false", False),
        ("https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-group", False),
        ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue", False),
        (
            "https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queueq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0?auto_setup=false",
            True,
        ),
        ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?mode=debug", True),
        ("https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false#details", True),
        ("https://reader" + "@" + "sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false", True),
        ("https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-groupq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
        ("https://support.halaxy.com/hc/en-au/articles/360044495693-Deactivate-a-user-from-your-group?mode=debug", True),
    ],
    ids=[
        "canonical-article",
        "article-id-too-short",
        "article-id-too-long",
        "sqs-queue-with-setup-query",
        "deactivate-user-article",
        "sqs-queue",
        "sqs-queue-opaque-tail",
        "sqs-queue-unknown-query",
        "sqs-queue-with-fragment",
        "sqs-queue-with-userinfo",
        "deactivate-article-opaque-tail",
        "deactivate-article-unknown-query",
    ],
)
def test_public_url_requires_complete_bounded_value(url: str, should_report: bool) -> None:
    """Keep public endpoints quiet while retaining warnings when their whole-value proof fails.

    Args:
        url: Authored endpoint or mutation; its account number is synthetic.
        should_report: Whether the full source must retain an entropy warning.
    """
    findings = HighEntropyStringRule().analyse(make_unit(f"value = {url!r}\n"), default_ctx())
    assert bool(findings) == should_report


@pytest.mark.parametrize(
    ("source", "should_report"),
    [
        ("# https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e\n", False),
        ("# https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e details\n", False),
        ("# opaquehttps://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e\n", True),
        ("# https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10eq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0\n", True),
        ('value = "prefix https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e suffix"\n', True),
        ("value = \"prefix 'https://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e' suffix\"\n", True),
        ('value = """prefix\nhttps://github.com/python/cpython/commit/6e8dcdaaa49d4313bf9fab9f9923ca5828fbb10e\nsuffix"""\n', True),
    ],
    ids=[
        "bare-reference",
        "bare-reference-followed-by-word",
        "glued-prefix",
        "bare-opaque-suffix",
        "enclosing-string",
        "nested-quotes",
        "multiline-enclosing-string",
    ],
)
def test_commit_reference_requires_complete_source_boundary(source: str, should_report: bool) -> None:
    """Keep public comment references quiet without hiding values inside larger strings.

    Args:
        source: Authored comment or enclosing string based on the reviewed public commit reference.
        should_report: Whether an entropy warning must survive the source-boundary check.
    """
    assert bool(HighEntropyStringRule().analyse(make_unit(source), default_ctx())) == should_report


@pytest.mark.parametrize(
    ("candidate", "should_report"),
    [
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", False),
        ("BACDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", True),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899", True),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", True),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
        ("security.access_token_handler.oidc.signature.ES256", False),
        ("security.access_token_handler.oidc.signature.ES384", False),
        ("security.access_token_handler.oidc.signature.ES512", False),
        ("security.access_token_handler.oidc.signature.RS256", False),
        ("security.access_token_handler.oidc.signature.RS384", False),
        ("security.access_token_handler.oidc.signature.RS512", False),
        ("security.access_token_handler.oidc.signature.PS256", False),
        ("security.access_token_handler.oidc.signature.PS384", False),
        ("security.access_token_handler.oidc.signature.PS512", False),
        ("security.access_token_handler.oidc.signature.HS512", True),
        ("security.access_token_handler.oidc.signature.PS513", True),
        ("security.access_token_handler.oidc.signature.ps512", True),
        ("other.security.access_token_handler.oidc.signature.PS512", True),
        ("security.access_token_handler.oidc.signature.PS512q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0security.access_token_handler.oidc.signature.PS512", True),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true",
            False,
        ),
    ],
    ids=[
        "review4-24-base62-alphabet",
        "base62-permutation",
        "base62-duplicate",
        "base62-opaque-prefix",
        "base62-opaque-tail",
        "review4-signature-ES256",
        "review4-signature-ES384",
        "review4-signature-ES512",
        "review4-signature-RS256",
        "review4-signature-RS384",
        "review4-signature-RS512",
        "review4-signature-PS256",
        "review4-signature-PS384",
        "review4-signature-PS512",
        "signature-unknown-code",
        "signature-wrong-size",
        "signature-wrong-case",
        "signature-wrong-prefix",
        "signature-opaque-tail",
        "signature-opaque-prefix",
        "review4-18-entra-route",
    ],
)
def test_approved_portal_and_service_values(candidate: str, should_report: bool) -> None:
    """Keep approved public values quiet without accepting their opaque mutations.

    Args:
        candidate: Complete alphabet, service identifier or portal URL; the UUID is synthetic.
        should_report: Whether the actual detector must retain a warning.
    """
    assert bool(HighEntropyStringRule().analyse(make_unit(f"value = {candidate!r}\n"), default_ctx())) == should_report


@pytest.mark.parametrize(
    ("candidate", "should_report"),
    [
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", False),
        ("/hc/en-au/articles/123456789012-Guide-to-fax-messages-in-Halaxy", False),
        ("/hc/en-au/articles/1234567890123-Deactivate-a-user-from-your-group", False),
        ("https://support.halaxy.com/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", False),
        ("/support/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", True),
        ("/hc/en-au/articles/123456" + "78901-Guide-to-fax-messages-in-Halaxy", True),
        ("/hc/en-au/articles/12345678901234-Guide-to-fax-messages-in-Halaxy", True),
        ("/hc/en-au/articles/1234567890123-Guide-by-fax-messages", True),
        ("/hc/en-au/articles/1234567890123-Guide-TO-fax-messages", True),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy", True),
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxyq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
        ("/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy-q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
        ("/hc/en-au/sections/123456789012-Guide-to-fax-messages-in-Halaxy", True),
        ("abcdefghijklmnopqrstuvwxyz0123456789", False),
        ("bacdefghijklmnopqrstuvwxyz0123456789", True),
        ("abcdefghijklmnopqrstuvwxyz01234567899", True),
        ("q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0abcdefghijklmnopqrstuvwxyz0123456789", True),
        ("abcdefghijklmnopqrstuvwxyz0123456789q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0", True),
    ],
    ids=[
        "review5-4-article-route",
        "article-twelve-digit-id",
        "article-approved-a",
        "article-complete-url",
        "article-wrong-prefix",
        "article-eleven-digit-id",
        "article-fourteen-digit-id",
        "article-unapproved-short-word",
        "article-uppercase-joiner",
        "article-opaque-prefix",
        "article-opaque-tail",
        "article-split-opaque-tail",
        "article-joiner-not-section",
        "review5-24-lowercase-digit-alphabet",
        "lowercase-digit-permutation",
        "lowercase-digit-duplicate",
        "lowercase-digit-opaque-prefix",
        "lowercase-digit-opaque-tail",
    ],
)
def test_approved_article_and_alphabet_values(candidate: str, should_report: bool) -> None:
    """Keep complete approved references quiet while preserving warnings on their opaque mutations.

    Args:
        candidate: Complete authored value; article identifiers are synthetic.
        should_report: Whether the detector must retain a warning for this source value.
    """
    assert bool(HighEntropyStringRule().analyse(make_unit(f"value = {candidate!r}\n"), default_ctx())) == should_report


@pytest.mark.parametrize(
    "url",
    [
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\n"
        ),
        (
            "http://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://reader:@entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com:443/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com.invalid/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/?mode=debug#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcde/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89AB-CDEF-0123-456789ABCDEF/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/true?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=false"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true&mode=debug"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true#details"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=trueq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0"
        ),
        (
            "prefix https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true suffix"
        ),
        (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
            "q7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z001234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true"
        ),
    ],
    ids=[
        "trailing-newline",
        "http-scheme",
        "userinfo",
        "explicit-port",
        "lookalike-host",
        "query-before-fragment",
        "short-app-id",
        "uppercase-app-id",
        "overview-blade",
        "msa-app-true",
        "legacy-redirect-false",
        "extra-query-parameter",
        "extra-fragment",
        "opaque-tail",
        "embedded-in-text",
        "opaque-app-id-prefix",
    ],
)
def test_portal_route_guard_rejects_extra_components(url: str) -> None:
    """Require the complete portal format even when a caller bypasses native token extraction.

    Args:
        url: Authored malformed route; its UUID is synthetic and carries no account information.
    """
    from gruffpy.rule.sensitive_data._entropy_public_shapes import is_public_entropy_url

    assert not is_public_entropy_url(url)


@pytest.mark.parametrize(
    ("source", "should_report"),
    [
        (
            (
                "# Application settings: https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
                "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\n"
            ),
            False,
        ),
        (
            (
                "# https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
                "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true details\n"
            ),
            False,
        ),
        (
            (
                "# opaquehttps://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
                "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\n"
            ),
            True,
        ),
        (
            (
                "# https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
                "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=trueq7W9e2R4t6Y8u1I3o5P0a9S7d5F3g1H8j6K4l2Z0\n"
            ),
            True,
        ),
        (
            (
                'value = "prefix https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/'
                '01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true suffix"\n'
            ),
            True,
        ),
        (
            (
                "value = \"prefix 'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/"
                "01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true' suffix\"\n"
            ),
            True,
        ),
        (
            (
                'value = """prefix\nhttps://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/'
                '01234567-89ab-cdef-0123-456789abcdef/isMSAApp~/false?Microsoft_AAD_IAM_legacyAADRedirect=true\nsuffix"""\n'
            ),
            True,
        ),
    ],
    ids=[
        "labelled-comment",
        "comment-with-trailing-text",
        "comment-opaque-prefix",
        "comment-opaque-tail",
        "inside-larger-string",
        "quoted-inside-larger-string",
        "inside-multiline-string",
    ],
)
def test_portal_reference_requires_complete_source_boundary(source: str, should_report: bool) -> None:
    """Keep portal comments quiet without hiding values inside larger strings.

    Args:
        source: Authored comment or enclosing string; its application UUID is synthetic.
        should_report: Whether the actual detector must retain an entropy warning.
    """
    assert bool(HighEntropyStringRule().analyse(make_unit(source), default_ctx())) == should_report


def test_article_route_guard_accepts_complete_value() -> None:
    """Accept the complete stored help link, so the malformed variants below fail for their own defect."""
    from gruffpy.rule.sensitive_data._entropy_public_shapes import is_public_entropy_shape, is_public_entropy_url

    route = "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy"
    assert is_public_entropy_shape(route)
    assert is_public_entropy_url("https://support.halaxy.com" + route)


@pytest.mark.parametrize(
    "invalid_route",
    [
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy\n",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy?mode=debug",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy#details",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy/details",
        "prefix /hc/en-au/articles/1234567890123-Guide-to-fax-messages-in-Halaxy suffix",
        "/hc/en-au/articles/1234567890123--to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-gUiDe-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-AlphabeticRepresentationReference-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-Guide2-to-fax-messages-in-Halaxy",
        "/hc/en-au/articles/1234567890123-Guide-to-fax-messages-IN-Halaxy",
    ],
    ids=[
        "trailing-newline",
        "query-string",
        "fragment",
        "extra-path-segment",
        "embedded-in-text",
        "empty-title-word",
        "mixed-case-title-word",
        "overlong-title-word",
        "digit-in-title-word",
        "uppercase-joiner-word",
    ],
)
def test_article_route_guard_requires_complete_value(invalid_route: str) -> None:
    """Keep malformed stored help links eligible for warnings independently of token extraction.

    Args:
        invalid_route: The complete article route with one extra component or one malformed title word.
    """
    from gruffpy.rule.sensitive_data._entropy_public_shapes import is_public_entropy_shape, is_public_entropy_url

    # Extra components or malformed title words cannot inherit the readable article's exception.
    assert not is_public_entropy_shape(invalid_route)
    assert not is_public_entropy_url("https://support.halaxy.com" + invalid_route)


def test_public_endpoint_after_comment_apostrophe() -> None:
    """Keep a quoted endpoint public when the preceding YAML comment contains an apostrophe."""
    source = "# Queue's settings\nvalue = 'https://sqs.ap-southeast-2.amazonaws.com/123456789012/media-concat-processing-queue?auto_setup=false'\n"
    assert not HighEntropyStringRule().analyse(make_unit(source), default_ctx())


def _toml_lines(project: Path, name: str, source: str) -> list[int]:
    """Write one TOML file into a synthetic project and return the entropy warnings' line numbers.

    Args:
        project: Project root that the rule context and the file's display path share.
        name: Project-relative file name to write and scan.
        source: TOML text to scan.

    Returns:
        Sorted one-based lines of every high-entropy warning in the file.
    """
    path = project / name
    path.write_text(source)
    unit = AnalysisUnit(file=SourceFile(absolute_path=str(path), display_path=name, type="text"), source=source, tree=None)
    context = replace(default_ctx(), project_root=str(project))
    return sorted(finding.line or 0 for finding in HighEntropyStringRule().analyse(unit, context))


def _write_tutorial(project: Path, relative: str) -> None:
    """Create one existing tutorial file that a path setting in the synthetic project can name.

    Args:
        project: Project root that holds the file.
        relative: Project-relative path of the file to create, with any missing parent folders.
    """
    (project / relative).parent.mkdir(parents=True, exist_ok=True)
    (project / relative).write_text("print('tutorial')\n")


def test_pyproject_path_settings_naming_existing_paths_stay_quiet(tmp_path: Path) -> None:
    """Keep sixth-review case 18's coverage omit entry quiet only while a listed setting names an existing project path.

    Fixture purpose: fastapi's coverage, ruff and ty settings name real tutorial files. Stable contract: a missing path,
    an unlisted key or table, a symlinked folder, a path leaving the project and an opaque token keep their warnings.

    Args:
        tmp_path: Temporary directory holding the synthetic project and one file outside it.
    """
    project = tmp_path / "project"
    _write_tutorial(project, "docs_src/response_model/tutorial003_04_py310.py")
    _write_tutorial(project, "docs_src/dependencies/tutorial013_an_py310.py")
    (project / "docs_src/tutorial003_04_py310_examples").mkdir()
    (project / "docs_src/linked_examples").symlink_to(project / "docs_src/dependencies", target_is_directory=True)
    (tmp_path / "outside/response_model").mkdir(parents=True)
    (tmp_path / "outside/response_model/tutorial003_04_py310.py").write_text("print('outside')\n")
    # Each source line pairs with whether it must keep its entropy warning.
    expected_source = [
        ("[tool.coverage.run]", False),
        ('source = ["fastapi"]', False),
        ("omit = [", False),
        ('    "docs_src/response_model/tutorial003_04_py310.py",', False),
        ('    "docs_src/response_model/tutorial999_04_py310.py",', True),
        ("]", False),
        ('data_file = "docs_src/response_model/tutorial003_04_py310.py"', True),
        ("[tool.coverage.report]", False),
        (f'omit = ["docs_src/dependencies/tutorial013_an_py310.py", "{_HIGH_ENTROPY}"]', True),
        ("[tool.ruff.lint.per-file-ignores]", False),
        ('"docs_src/dependencies/tutorial013_an_py310.py" = ["B904"]', False),
        ('"docs_src/linked_examples/tutorial013_an_py310.py" = ["B904"]', True),
        ("[tool.ty.src]", False),
        ("exclude = [", False),
        ('    "docs_src/tutorial003_04_py310_examples/",', False),
        ('    "../outside/response_model/tutorial003_04_py310.py",', True),
        ("]", False),
        ("[tool.other]", False),
        ('path = "docs_src/response_model/tutorial003_04_py310.py"', True),
    ]
    source = "\n".join(line for line, _ in expected_source)
    warned_lines = [number for number, (_, warns) in enumerate(expected_source, start=1) if warns]

    assert _toml_lines(project, "pyproject.toml", source + "\n") == warned_lines


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("ruff.toml", '[lint.per-file-ignores]\n"docs_src/dependencies/tutorial013_an_py310.py" = ["B904"]\n'),
        ("pyproject.toml", '[tool.ty.src]\nexclude = ["docs_src/dependencies/tutorial013_an_py310.py"\n'),
    ],
    ids=["other-toml-file", "unparsed-pyproject"],
)
def test_path_settings_need_a_parsed_pyproject(tmp_path: Path, name: str, source: str) -> None:
    """Keep an existing path's warning when the file is not a pyproject.toml or its TOML does not parse.

    Args:
        tmp_path: Temporary project holding the named file.
        name: File name that carries the path setting.
        source: TOML text whose second line names an existing file.
    """
    (tmp_path / "docs_src/dependencies").mkdir(parents=True)
    (tmp_path / "docs_src/dependencies/tutorial013_an_py310.py").write_text("print('tutorial')\n")

    assert _toml_lines(tmp_path, name, source) == [2]


def test_pyproject_parent_steps_preserve_filesystem_proof(tmp_path: Path) -> None:
    directory = tmp_path / "docs_src" / "dependencies"
    directory.mkdir(parents=True)
    filename = "tutorial013_an_py310.py"
    (directory / filename).write_text("pass\n")
    (tmp_path / "linked").symlink_to(directory, target_is_directory=True)
    # Each omitted path pairs with whether it must keep its entropy warning.
    expected_paths = [
        (f"linked/../docs_src/dependencies/{filename}", True),
        (f"missing/../docs_src/dependencies/{filename}", True),
        (f"docs_src/dependencies/{filename}/../{filename}", True),
        (f"docs_src/dependencies/../dependencies/{filename}", False),
    ]
    header = ["[tool.coverage.run]", "omit = ["]
    source = "\n".join([*header, *(f'    "{path}",' for path, _ in expected_paths), "]"]) + "\n"
    warned_lines = [len(header) + number for number, (_, warns) in enumerate(expected_paths, start=1) if warns]
    assert _toml_lines(tmp_path, "pyproject.toml", source) == warned_lines
