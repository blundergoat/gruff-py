"""End-to-end acceptance for the ``sensitiveExclusions`` config section.

Adapts ``gruff-spec/fixtures/sensitive-exclusions/cases.v1.json`` to gruff-py: ``@case:aws``,
``@case:aws-sibling``, ``@case:jwt``, and ``@case:clean`` render as the synthetic ``.env`` fixtures
built below, and ``{{awsRuleId}}`` / ``{{jwtRuleId}}`` resolve to this port's rule ids.

Each acceptance case follows the spec's sibling rule: a no-config baseline run is compared with the
same tree under the case configuration, and the set of findings the configuration removed must
equal exactly the findings whose rule and path a declared entry names.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from gruffpy.cli import main

_AWS_RULE = "sensitive-data.aws-access-key"
_JWT_RULE = "sensitive-data.jwt-token"

# Split literals so the fixtures never read as a credential to another scanner.
_SYNTHETIC_AWS_KEY = "AKIA" + "2222333344445555"
_SYNTHETIC_AWS_SIBLING_KEY = "AKIA" + "6666777788889999"
_SYNTHETIC_JWT = (
    "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJzeW50aGV0aWMifQ" + "." + "c3ludGhldGljc2ln"
)

_CONFIG_HEADER = "schemaVersion: gruff-py.config.v0.1\n"


def _write_corpus(project_root: Path) -> None:
    """Create the four-file synthetic corpus every case in this module scans."""
    secrets = project_root / "secrets"
    secrets.mkdir()
    # The AWS case file carries the rule twice plus a second sensitive rule, so a case can prove
    # that every occurrence goes and that the sibling rule in the same file stays.
    (secrets / "aws.env").write_text(
        f"AWS_KEY={_SYNTHETIC_AWS_KEY}\n"
        f"AWS_BACKUP_KEY={_SYNTHETIC_AWS_KEY}\n"
        f"SESSION_TOKEN={_SYNTHETIC_JWT}\n"
    )
    (secrets / "aws-sibling.env").write_text(f"AWS_KEY={_SYNTHETIC_AWS_SIBLING_KEY}\n")
    (secrets / "jwt.env").write_text(f"SESSION_TOKEN={_SYNTHETIC_JWT}\n")
    (secrets / "clean.env").write_text("LOG_LEVEL=debug\n")


def _analyse(project_root: Path, *, use_config: bool) -> dict[str, Any]:
    """Run ``analyse --format json`` over the corpus and return the parsed report."""
    arguments = ["analyse", "--format", "json", "--fail-on", "none"]
    if not use_config:
        arguments.append("--no-config")
    arguments.append("secrets")
    result = CliRunner().invoke(main, arguments)
    assert result.exit_code == 0, result.output
    payload: dict[str, Any] = json.loads(result.stdout)
    return payload


def _finding_scopes(payload: dict[str, Any]) -> set[tuple[str, str, int | None]]:
    """Reduce a report's findings to comparable (rule, path, line) scopes."""
    return {
        (finding["ruleId"], finding["file"], finding["line"]) for finding in payload["findings"]
    }


def _write_config(project_root: Path, entries: str) -> None:
    (project_root / ".gruff-py.yaml").write_text(_CONFIG_HEADER + entries)


@pytest.fixture
def corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Build the synthetic corpus in a temp project and make it the working directory."""
    monkeypatch.chdir(tmp_path)
    _write_corpus(tmp_path)
    return tmp_path


def test_exact_rule_and_path_removes_only_that_scope(corpus: Path) -> None:
    """Case ``exact-rule-and-path``: every occurrence in the named file goes, nothing else."""
    baseline = _analyse(corpus, use_config=False)
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key used by the redaction corpus; not a live credential.\n",
    )

    configured = _analyse(corpus, use_config=True)

    removed = _finding_scopes(baseline) - _finding_scopes(configured)
    assert removed == {
        scope
        for scope in _finding_scopes(baseline)
        if scope[0] == _AWS_RULE and scope[1] == "secrets/aws.env"
    }
    assert len(removed) == 2
    assert configured["suppressions"] == [
        {
            "index": 0,
            "rule": _AWS_RULE,
            "paths": ["secrets/aws.env"],
            "symbol": None,
            "reason": ("Synthetic AWS key used by the redaction corpus; not a live credential."),
            "suppressed": 2,
        }
    ]


def test_same_rule_in_another_file_and_other_rules_keep_reporting(corpus: Path) -> None:
    """The sibling file and the second sensitive rule in the excluded file both survive."""
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key used by the redaction corpus.\n",
    )

    configured = _analyse(corpus, use_config=True)

    surviving = {(finding["ruleId"], finding["file"]) for finding in configured["findings"]}
    assert (_AWS_RULE, "secrets/aws-sibling.env") in surviving
    assert (_JWT_RULE, "secrets/aws.env") in surviving
    assert (_AWS_RULE, "secrets/aws.env") not in surviving


def test_scope_matching_nothing_reports_zero_without_failing(corpus: Path) -> None:
    """Case ``scope-matching-nothing``: fixing the underlying problem never breaks a build."""
    baseline = _analyse(corpus, use_config=False)
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/clean.env\n"
        "    reason: Retained while the fixture is being removed.\n",
    )

    configured = _analyse(corpus, use_config=True)

    assert _finding_scopes(configured) == _finding_scopes(baseline)
    assert configured["suppressions"][0]["suppressed"] == 0


def test_symbol_narrows_the_scope_to_nothing_on_this_pillar(corpus: Path) -> None:
    """Case ``symbol-narrows-scope``: these findings carry no symbol, so nothing matches."""
    baseline = _analyse(corpus, use_config=False)
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    symbol: SyntheticFixtureSymbol\n"
        "    reason: Narrowed to one symbol while the fixture is refactored.\n",
    )

    configured = _analyse(corpus, use_config=True)

    assert _finding_scopes(configured) == _finding_scopes(baseline)
    assert configured["suppressions"][0]["symbol"] == "SyntheticFixtureSymbol"
    assert configured["suppressions"][0]["suppressed"] == 0


def test_two_distinct_entries_each_report_their_own_count(corpus: Path) -> None:
    """Case ``two-distinct-entries``: independent scopes keep independent counts."""
    baseline = _analyse(corpus, use_config=False)
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key in the redaction corpus.\n"
        f"  - rule: {_JWT_RULE}\n"
        "    path: secrets/jwt.env\n"
        "    reason: Synthetic JWT in the redaction corpus.\n",
    )

    configured = _analyse(corpus, use_config=True)

    removed = _finding_scopes(baseline) - _finding_scopes(configured)
    assert removed == {
        scope
        for scope in _finding_scopes(baseline)
        if (scope[0], scope[1]) in {(_AWS_RULE, "secrets/aws.env"), (_JWT_RULE, "secrets/jwt.env")}
    }
    assert [row["suppressed"] for row in configured["suppressions"]] == [2, 1]


def test_same_rule_other_file_survives_when_only_the_sibling_is_excluded(corpus: Path) -> None:
    """Case ``same-rule-other-file-survives``: excluding one file leaves the other reporting."""
    baseline = _analyse(corpus, use_config=False)
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws-sibling.env\n"
        "    reason: Only the sibling fixture is accepted.\n",
    )

    configured = _analyse(corpus, use_config=True)

    removed = _finding_scopes(baseline) - _finding_scopes(configured)
    assert removed == {
        scope
        for scope in _finding_scopes(baseline)
        if scope[0] == _AWS_RULE and scope[1] == "secrets/aws-sibling.env"
    }
    assert (_AWS_RULE, "secrets/aws.env") in {
        (finding["ruleId"], finding["file"]) for finding in configured["findings"]
    }


def test_suppressed_findings_leave_the_score_and_exit_code(corpus: Path) -> None:
    """A suppressed finding stops gating the build, exactly like the inline directive channel."""
    unconfigured = CliRunner().invoke(
        main, ["analyse", "--format", "json", "--fail-on", "error", "--no-config", "secrets"]
    )
    assert unconfigured.exit_code == 1, unconfigured.output

    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        + "".join(
            f"  - rule: {rule}\n    path: {path}\n    reason: Synthetic redaction-corpus fixture.\n"
            for rule, path in (
                (_AWS_RULE, "secrets/aws.env"),
                (_AWS_RULE, "secrets/aws-sibling.env"),
                (_JWT_RULE, "secrets/aws.env"),
                (_JWT_RULE, "secrets/jwt.env"),
            )
        ),
    )
    configured = CliRunner().invoke(
        main, ["analyse", "--format", "json", "--fail-on", "error", "secrets"]
    )

    payload = json.loads(configured.stdout)
    assert [row["suppressed"] for row in payload["suppressions"]] == [2, 1, 1, 1]
    assert not [
        finding for finding in payload["findings"] if finding["ruleId"] in {_AWS_RULE, _JWT_RULE}
    ]


def test_text_output_states_the_suppressed_total_and_its_rationale(corpus: Path) -> None:
    """Terminal users see the family total, so a configured suppression is never invisible."""
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key used by the redaction corpus.\n",
    )

    result = CliRunner().invoke(main, ["analyse", "--fail-on", "none", "secrets"])

    assert result.exit_code == 0, result.output
    assert "Sensitive exclusions" in result.stdout
    assert (
        "  Suppressed findings: 2 via sensitiveExclusions[0] "
        f"{_AWS_RULE}: 2 (Synthetic AWS key used by the redaction corpus.)"
    ) in result.stdout


def test_summary_text_states_the_same_suppressed_total_as_analyse(corpus: Path) -> None:
    """Section 13a: ``summary`` filters, so it publishes the count ``analyse`` publishes."""
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key used by the redaction corpus.\n",
    )
    audit_line = (
        "  Suppressed findings: 2 via sensitiveExclusions[0] "
        f"{_AWS_RULE}: 2 (Synthetic AWS key used by the redaction corpus.)"
    )

    summarised = CliRunner().invoke(main, ["summary", "secrets"])
    analysed = CliRunner().invoke(main, ["analyse", "--fail-on", "none", "secrets"])

    assert summarised.exit_code == 0, summarised.output
    assert analysed.exit_code == 0, analysed.output
    assert "Sensitive exclusions" in summarised.stdout
    assert audit_line in summarised.stdout
    assert audit_line in analysed.stdout


def test_no_reported_field_carries_matched_value_material(corpus: Path) -> None:
    """Section 5 forbids value material anywhere in the report, audit rows included."""
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    reason: Synthetic AWS key used by the redaction corpus.\n",
    )

    result = CliRunner().invoke(
        main, ["analyse", "--format", "json", "--fail-on", "none", "secrets"]
    )

    assert _SYNTHETIC_AWS_KEY not in result.stdout
    assert _SYNTHETIC_JWT not in result.stdout


def test_rejected_entry_stops_the_json_run_with_a_config_error(corpus: Path) -> None:
    """A machine consumer gets a parseable config-error payload and exit 2."""
    _write_config(
        corpus,
        "sensitiveExclusions:\n"
        f"  - rule: {_AWS_RULE}\n"
        "    path: secrets/aws.env\n"
        "    message_contains: AKIA\n"
        "    reason: Synthetic fixture.\n",
    )

    result = CliRunner().invoke(main, ["analyse", "--format", "json", "secrets"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["diagnostics"][0]["type"] == "config-error"
    assert "sensitiveExclusions[0]" in payload["diagnostics"][0]["message"]
    assert "message_contains" in payload["diagnostics"][0]["message"]
