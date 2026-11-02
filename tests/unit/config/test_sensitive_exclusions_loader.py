"""Verify the ``sensitiveExclusions`` entries users may write, and every rejection.

Cases mirror ``gruff-spec/fixtures/sensitive-exclusions/cases.v1.json``: the accepted shape, and
each numbered rejection in FAMILY-CONTRACT section 13a. Every rejection must name the entry index
and the offending key so the user can find the line to edit.
"""

from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.exceptions import ConfigError
from gruffpy.config.loader import ConfigLoader
from gruffpy.config.sensitive_exclusions import SensitiveExclusion
from gruffpy.rule.registry import RuleRegistry

_AWS_RULE = "sensitive-data.aws-access-key"
_JWT_RULE = "sensitive-data.jwt-token"
_NON_SENSITIVE_RULE = "security.dangerous-function-call"


def _defaults() -> AnalysisConfig:
    """Build the analysis config the registry's defaults produce.

    Returns:
        The default configuration.
    """
    return AnalysisConfig.from_registry(RuleRegistry.defaults())


def _yaml(tmp_path: Path, body: str) -> Path:
    """Write a project's ``.gruff-py.yaml`` as the schema version line followed by the given body.

    Args:
        tmp_path: Project root that receives the config.
        body: YAML text appended after the schema version line.

    Returns:
        The written config path.
    """
    path = tmp_path / ".gruff-py.yaml"
    path.write_text("schemaVersion: gruff-py.config.v0.1\n" + body)
    return path


def _load(tmp_path: Path, body: str) -> AnalysisConfig:
    """Write a config body and load it over the registry defaults.

    Args:
        tmp_path: Project root that receives the config.
        body: YAML text appended after the schema version line.

    Returns:
        The loaded configuration.
    """
    _yaml(tmp_path, body)
    config, _ = ConfigLoader(tmp_path, _defaults()).load()
    return config


def _entry(**fields: str) -> str:
    """Format one ``sensitiveExclusions`` list item as YAML, with ``rule`` first and the other fields beneath it.

    Args:
        fields: Entry fields as written in YAML; ``rule`` is required.

    Returns:
        The entry's YAML lines, ending with a newline.
    """
    lines = [f"  - rule: {fields['rule']}"]
    lines.extend(f"    {key}: {value}" for key, value in fields.items() if key != "rule")
    return "\n".join(lines) + "\n"


def test_absent_section_leaves_no_sensitive_exclusions(tmp_path: Path) -> None:
    """Load no sensitive exclusions when the config has no ``sensitiveExclusions`` section.

    Args:
        tmp_path: Project root whose config sets only an empty ignore list.
    """
    config = _load(tmp_path, "paths:\n  ignore: []\n")

    assert config.sensitive_exclusions == ()


def test_empty_section_is_accepted(tmp_path: Path) -> None:
    """Accept an empty ``sensitiveExclusions`` list as no exclusions.

    Args:
        tmp_path: Project root whose config sets the section to an empty list.
    """
    config = _load(tmp_path, "sensitiveExclusions: []\n")

    assert config.sensitive_exclusions == ()


def test_rule_and_path_entry_loads_with_its_reason(tmp_path: Path) -> None:
    """Load a rule-and-path entry with index 0, no symbol and its unquoted reason.

    Args:
        tmp_path: Project root whose config holds one AWS-rule entry with a reason.
    """
    config = _load(
        tmp_path,
        "sensitiveExclusions:\n"
        + _entry(
            rule=_AWS_RULE,
            path="secrets/aws.env",
            reason='"Synthetic AWS key used by the redaction corpus; not a live credential."',
        ),
    )

    assert config.sensitive_exclusions == (
        SensitiveExclusion(
            index=0,
            rule=_AWS_RULE,
            path="secrets/aws.env",
            symbol=None,
            reason="Synthetic AWS key used by the redaction corpus; not a live credential.",
        ),
    )


def test_symbol_is_accepted_and_retained(tmp_path: Path) -> None:
    """Keep the symbol an entry names.

    Args:
        tmp_path: Project root whose entry narrows the AWS rule to one symbol.
    """
    config = _load(
        tmp_path,
        "sensitiveExclusions:\n"
        + _entry(
            rule=_AWS_RULE,
            path="secrets/aws.env",
            symbol="SyntheticFixtureSymbol",
            reason='"Narrowed to one symbol while the fixture is refactored."',
        ),
    )

    assert config.sensitive_exclusions[0].symbol == "SyntheticFixtureSymbol"


def test_two_distinct_entries_keep_their_written_order(tmp_path: Path) -> None:
    """Index two entries in their written order.

    Args:
        tmp_path: Project root whose config holds an AWS entry and then a JWT entry.
    """
    config = _load(
        tmp_path,
        "sensitiveExclusions:\n"
        + _entry(rule=_AWS_RULE, path="secrets/aws.env", reason='"Synthetic AWS key."')
        + _entry(rule=_JWT_RULE, path="secrets/jwt.env", reason='"Synthetic JWT."'),
    )

    assert [(entry.index, entry.rule) for entry in config.sensitive_exclusions] == [
        (0, _AWS_RULE),
        (1, _JWT_RULE),
    ]


def test_written_path_is_normalised_to_the_display_path_findings_carry(tmp_path: Path) -> None:
    """Normalise an entry path written with a leading ``./`` to ``secrets/aws.env``.

    Args:
        tmp_path: Project root whose entry path starts with ``./``.
    """
    config = _load(
        tmp_path,
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path='"./secrets/aws.env"', reason='"Synthetic AWS key."'),
    )

    assert config.sensitive_exclusions[0].path == "secrets/aws.env"


def test_toml_entries_load_with_the_same_shape(tmp_path: Path) -> None:
    """Load a ``pyproject.toml`` exclusion entry into the same structure as a YAML entry.

    Args:
        tmp_path: Project root whose ``pyproject.toml`` holds one inline-table entry.
    """
    (tmp_path / "pyproject.toml").write_text(
        '[tool.gruff-py]\nschemaVersion = "gruff-py.config.v0.1"\n'
        "sensitiveExclusions = [\n"
        f'  {{ rule = "{_AWS_RULE}", path = "secrets/aws.env", reason = "Synthetic key." }},\n'
        "]\n"
    )

    config, _ = ConfigLoader(tmp_path, _defaults()).load()

    assert config.sensitive_exclusions == (
        SensitiveExclusion(
            index=0,
            rule=_AWS_RULE,
            path="secrets/aws.env",
            symbol=None,
            reason="Synthetic key.",
        ),
    )


# The case table is a module constant so the test itself stays readable at a glance.
_REJECTION_CASES = [
    (
        "missing-reason",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path="secrets/aws.env"),
        ("sensitiveExclusions[0].reason", "reason"),
    ),
    (
        "blank-reason",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path="secrets/aws.env", reason='"   "'),
        ("sensitiveExclusions[0].reason", "reason"),
    ),
    (
        "wildcard-rule",
        "sensitiveExclusions:\n" + _entry(rule='"*"', path="secrets/aws.env", reason='"Synthetic fixture."'),
        ("sensitiveExclusions[0].rule", "metacharacter"),
    ),
    (
        "pillar-selector-rule",
        "sensitiveExclusions:\n" + _entry(rule="sensitive-data", path="secrets/aws.env", reason='"Synthetic."'),
        ("sensitiveExclusions[0].rule", "selector"),
    ),
    (
        "glob-selector-rule",
        "sensitiveExclusions:\n" + _entry(rule='"sensitive-data.*"', path="secrets/aws.env", reason='"Synthetic."'),
        ("sensitiveExclusions[0].rule", "metacharacter"),
    ),
    (
        "unknown-rule",
        "sensitiveExclusions:\n"
        + _entry(
            rule="sensitive-data.not-a-real-rule",
            path="secrets/aws.env",
            reason='"Synthetic."',
        ),
        ("sensitiveExclusions[0].rule", "unknown rule id"),
    ),
    (
        "non-sensitive-rule",
        "sensitiveExclusions:\n" + _entry(rule=_NON_SENSITIVE_RULE, path="secrets/aws.env", reason='"Synthetic."'),
        ("sensitiveExclusions[0].rule", "sensitive-data"),
    ),
    (
        "absolute-path",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path='"/etc/secrets/aws.env"', reason='"Synthetic."'),
        ("sensitiveExclusions[0].path", "absolute"),
    ),
    (
        "windows-absolute-path",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path='"C:\\\\secrets\\\\aws.env"', reason='"Synthetic."'),
        ("sensitiveExclusions[0].path", "absolute"),
    ),
    (
        "parent-escape-path",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path='"../secrets/aws.env"', reason='"Synthetic."'),
        ("sensitiveExclusions[0].path", "traverses"),
    ),
    (
        "glob-path",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path='"secrets/*.env"', reason='"Synthetic."'),
        ("sensitiveExclusions[0].path", "glob"),
    ),
    (
        "message-contains-matching",
        "sensitiveExclusions:\n"
        + _entry(
            rule=_AWS_RULE,
            path="secrets/aws.env",
            message_contains='"AKIA"',
            reason='"Synthetic."',
        ),
        ("sensitiveExclusions[0]", "message_contains"),
    ),
    (
        "camel-case-message-matching",
        "sensitiveExclusions:\n"
        + _entry(
            rule=_AWS_RULE,
            path="secrets/aws.env",
            messageContains='"AKIA"',
            reason='"Synthetic."',
        ),
        ("sensitiveExclusions[0]", "messageContains"),
    ),
    (
        "value-matching",
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path="secrets/aws.env", value='"AKIA"', reason='"Synthetic."'),
        ("sensitiveExclusions[0]", "value"),
    ),
    (
        "preview-matching",
        "sensitiveExclusions:\n"
        + _entry(
            rule=_AWS_RULE,
            path="secrets/aws.env",
            preview='"[redacted:aws-access-key]"',
            reason='"Synthetic."',
        ),
        ("sensitiveExclusions[0]", "preview"),
    ),
    (
        "duplicate-scope",
        "sensitiveExclusions:\n"
        + _entry(rule=_AWS_RULE, path="secrets/aws.env", reason='"First rationale."')
        + _entry(rule=_AWS_RULE, path="secrets/aws.env", reason='"Second rationale."'),
        ("sensitiveExclusions[1]", "duplicate"),
    ),
]


@pytest.mark.parametrize(
    ("case_id", "body", "mentions"),
    _REJECTION_CASES,
    ids=[case[0] for case in _REJECTION_CASES],
)
def test_rejected_entry_names_its_index_and_offending_key(
    tmp_path: Path,
    case_id: str,
    body: str,
    mentions: tuple[str, ...],
) -> None:
    """Every contract rejection stops the run with a diagnostic the user can act on.

    Args:
        tmp_path: Project root the malformed config is written into.
        case_id: Name of the rejection case, reported when the assertion fails.
        body: Config text expected to be refused.
        mentions: Substrings the diagnostic must contain, naming the entry and the offending key.
    """
    _yaml(tmp_path, body)

    with pytest.raises(ConfigError) as excinfo:
        ConfigLoader(tmp_path, _defaults()).load()

    message = str(excinfo.value)
    assert all(mention in message for mention in mentions), (case_id, message)


def test_section_must_be_a_list(tmp_path: Path) -> None:
    """Refuse a ``sensitiveExclusions`` section that is a mapping rather than a list.

    Args:
        tmp_path: Project root whose section is a single mapping.
    """
    _yaml(tmp_path, "sensitiveExclusions:\n  rule: sensitive-data.aws-access-key\n")

    with pytest.raises(ConfigError, match="must be a list of entries"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_entry_must_be_a_table(tmp_path: Path) -> None:
    """Refuse a list item that is not a table, naming its index.

    Args:
        tmp_path: Project root whose section lists a bare rule id.
    """
    _yaml(tmp_path, "sensitiveExclusions:\n  - sensitive-data.aws-access-key\n")

    with pytest.raises(ConfigError, match=r"sensitiveExclusions\[0\]. must be a table"):
        ConfigLoader(tmp_path, _defaults()).load()


def test_rejection_is_fatal_even_in_the_default_non_strict_scan(tmp_path: Path) -> None:
    """Unknown rule keys only warn, but an unreviewable suppression always stops the scan.

    Args:
        tmp_path: Project root carrying a suppression entry with no rationale.
    """
    _yaml(
        tmp_path,
        "sensitiveExclusions:\n" + _entry(rule=_AWS_RULE, path="secrets/aws.env"),
    )
    loader = ConfigLoader(tmp_path, _defaults(), strict=False)

    with pytest.raises(ConfigError):
        loader.load()
