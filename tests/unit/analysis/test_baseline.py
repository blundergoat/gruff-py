"""Cover baseline v3 as users meet it: reviewed debt that survives an edit, and secrets that never do.

The cases here are the family cases: a line-shifted finding stays hidden, a new sibling never inherits a review,
a reviewed count is spent lowest line first, a secret is never eligible, another port's file is refused, and a 0.5
baseline is carried forward into a second file that leaves the original byte-identical.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from gruffpy.analysis.baseline import (
    BaselineError,
    BaselineStore,
    apply_baseline,
    generate_baseline,
    migrate_baseline,
    require_overwritable_default_path,
)
from gruffpy.finding.baseline_identity import compute_identity_for, normalise_measured_values
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


@pytest.mark.parametrize(
    ("tool_language", "rule_id", "path", "subject", "expected"),
    [
        ("rs", "docs.missing-readme", "src/widget.rs", "process#1", "aff839f0cf33b11e"),
        ("rs", "docs.missing-readme", "src/widget.rs", "process#2", "4ab8dc0e1ec4b969"),
        ("rs", "docs.missing-readme", "src/widget.rs", "File has no module documentation", "bdb4503a37614a4f"),
        ("ts", "docs.missing-readme", "src/widget.rs", "process#1", "caa4bb2431af313d"),
        ("rs", "docs.missing-readme", "src/gadget.rs", "process#1", "8f717ea2d0f8af15"),
    ],
)
def test_identity_matches_the_family_oracle(tool_language: str, rule_id: str, path: str, subject: str, expected: str) -> None:
    assert compute_identity_for(tool_language, rule_id, path, subject) == expected


def test_measured_values_never_enter_a_symbol_less_identity() -> None:
    assert normalise_measured_values("File has 1010 lines (limit 1000)") == "File has # lines (limit #)"
    assert normalise_measured_values("12.5% over 1,234 lines in v0.5.2") == "#% over # lines in v#"
    assert normalise_measured_values("File has no module documentation") == "File has no module documentation"


def test_generated_baseline_stores_one_line_free_row_per_identity(tmp_path: Path) -> None:
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])
    payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert payload["occurrences"] == [
        {
            "identity": compute_identity_for("py", "docs.example", "src/example.py", "example#1"),
            "count": 1,
            "ruleId": "docs.example",
            "path": "src/example.py",
            "subject": "example#1",
        }
    ]


def test_a_generated_baseline_names_its_schema_writer_and_sensitive_policy(tmp_path: Path) -> None:
    report = generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])
    payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert (payload["schemaVersion"], payload["toolLanguage"], payload["sensitive"]["eligible"]) == ("gruff.baseline.v3", "py", False)
    assert (report.total_entries, report.stale_evaluation) == (1, "generated")


def test_a_line_shifted_finding_stays_hidden_and_a_new_sibling_does_not(tmp_path: Path) -> None:
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])

    moved = _finding(line=300)
    sibling = _finding(symbol="other", line=400)
    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[moved, sibling], source="explicit")

    assert result.findings == [sibling]
    assert result.report.unchanged_count == 1
    assert result.report.new_count == 1
    assert result.report.absent_count == 0


def test_a_second_occurrence_beyond_the_reviewed_count_is_new_and_the_lowest_line_is_spent(tmp_path: Path) -> None:
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])

    later = _finding(line=90)
    earlier = _finding(line=10)
    # The run is supplied out of order, so a port that spent the count in scan order would hide the wrong occurrence.
    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[later, earlier], source="explicit")

    assert result.report.unchanged_count == 1
    assert result.report.new_count == 1
    assert [finding.line for finding in result.findings] == [90]


def test_a_measured_file_level_finding_survives_the_file_growing(tmp_path: Path) -> None:
    reviewed = _finding(symbol=None, message="File has 1010 lines (limit 1000)", line=1)
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[reviewed])

    grown = _finding(symbol=None, message="File has 1200 lines (limit 1000)", line=1)
    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[grown], source="explicit")

    assert result.findings == []
    assert result.report.unchanged_count == 1


def test_symbol_less_occurrences_are_counted_never_collided(tmp_path: Path) -> None:
    reviewed = _finding(symbol=None, message="Function has 12 parameters", line=10)
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[reviewed])

    second = _finding(symbol=None, message="Function has 14 parameters", line=90)
    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[reviewed, second], source="explicit")

    assert result.report.collision_count == 0
    assert result.report.unchanged_count == 1
    assert result.report.new_count == 1


def test_a_sensitive_finding_is_never_stored_and_never_hidden(tmp_path: Path) -> None:
    secret = _finding(rule_id="sensitive-data.aws-access-key", pillar=Pillar.SENSITIVE_DATA, symbol=None, message="Possible AWS key")
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[secret])
    payload = json.loads((tmp_path / "gruff-baseline.json").read_text())

    assert payload["occurrences"] == []
    assert payload["sensitive"]["counts"] == {"total": 1, "byRule": {"sensitive-data.aws-access-key": 1}}

    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[secret], source="explicit")

    assert result.findings == [secret]
    assert result.report.not_eligible_count == 1
    assert result.report.unchanged_count == 0


def test_a_baseline_written_by_another_port_is_refused(tmp_path: Path) -> None:
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])
    payload = json.loads((tmp_path / "gruff-baseline.json").read_text())
    payload["toolLanguage"] = "ts"
    (tmp_path / "gruff-baseline.json").write_text(json.dumps(payload))

    with pytest.raises(BaselineError, match="written by ts"):
        apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()], source="explicit")


def test_a_row_that_could_expire_or_leak_fails_the_file(tmp_path: Path) -> None:
    (tmp_path / "gruff-baseline.json").write_text(
        json.dumps(
            {
                "schemaVersion": "gruff.baseline.v3",
                "toolLanguage": "py",
                "occurrences": [{"identity": "0" * 16, "count": 1, "line": 12}],
            }
        )
    )

    with pytest.raises(BaselineError, match='forbidden key "line"'):
        apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[], source="explicit")


def test_a_0_5_baseline_fails_closed_and_names_the_migration_command(tmp_path: Path) -> None:
    _write_legacy_input(tmp_path)

    with pytest.raises(BaselineError, match="--migrate-baseline"):
        apply_baseline(project_root=tmp_path, path="legacy.json", findings=[_finding()], source="explicit")


def test_migration_carries_reviews_forward_and_leaves_its_input_byte_identical(tmp_path: Path) -> None:
    legacy_bytes = _write_legacy_input(tmp_path)
    unreviewed = _finding(symbol="unreviewed", line=400)

    report = migrate_baseline(
        project_root=tmp_path,
        input_path="legacy.json",
        output_path="migrated.json",
        findings=[_finding(), unreviewed],
    )
    migrated = json.loads((tmp_path / "migrated.json").read_text())

    assert report.stale_evaluation == "migrated"
    assert report.total_entries == 1
    assert migrated["schemaVersion"] == "gruff.baseline.v3"
    # The 0.5 digest named a line and this one does not, so the migration re-identifies rather than translates.
    assert migrated["occurrences"][0]["identity"] == compute_identity_for("py", "docs.example", "src/example.py", "example#1")
    assert (tmp_path / "legacy.json").read_bytes() == legacy_bytes


def test_migration_refuses_to_write_over_its_own_input(tmp_path: Path) -> None:
    legacy_bytes = _write_legacy_input(tmp_path)
    link = tmp_path / "linked.json"
    link.symlink_to(tmp_path / "legacy.json")

    with pytest.raises(BaselineError, match="different file"):
        BaselineStore(tmp_path).migrate("legacy.json", "legacy.json", [_finding()])
    with pytest.raises(BaselineError, match="different file"):
        BaselineStore(tmp_path).migrate("legacy.json", "linked.json", [_finding()])
    assert (tmp_path / "legacy.json").read_bytes() == legacy_bytes


def test_migration_refuses_an_ambiguous_input(tmp_path: Path) -> None:
    ambiguous = json.dumps({"schemaVersion": "gruff-py.baseline.v1", "findings": [], "entries": []}, indent=4).encode("utf-8")
    (tmp_path / "legacy.json").write_bytes(ambiguous)

    with pytest.raises(BaselineError, match="more than one row container"):
        migrate_baseline(project_root=tmp_path, input_path="legacy.json", output_path="migrated.json", findings=[_finding()])

    assert (tmp_path / "legacy.json").read_bytes() == ambiguous
    # A refused migration writes nothing, so the user is not left with a half-migrated second file.
    assert not (tmp_path / "migrated.json").exists()


def test_migration_refuses_a_hard_linked_output(tmp_path: Path) -> None:
    legacy_bytes = _write_legacy_input(tmp_path)
    (tmp_path / "hard-link.json").hardlink_to(tmp_path / "legacy.json")

    with pytest.raises(BaselineError, match="different file"):
        BaselineStore(tmp_path).migrate("legacy.json", "hard-link.json", [_finding()])

    assert (tmp_path / "legacy.json").read_bytes() == legacy_bytes


def test_a_baseline_only_ever_removes_reviewed_findings(tmp_path: Path) -> None:
    """The ratified invariant: a baseline may remove reviewed ordinary findings from score and exit, and nothing else."""
    reviewed = _finding()
    fresh = _finding(symbol="other", line=400)
    secret = _finding(rule_id="sensitive-data.aws-access-key", pillar=Pillar.SENSITIVE_DATA, symbol=None, message="Possible AWS key")
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[reviewed, secret])

    result = apply_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[reviewed, fresh, secret], source="explicit")

    # Only the reviewed finding leaves the gated set; the new one and the secret still fail the run.
    assert result.findings == [fresh, secret]
    assert result.report.unchanged_count == 1
    assert result.report.new_count == 1
    assert result.report.not_eligible_count == 1


def test_default_path_protection_keeps_the_retreat_copy(tmp_path: Path) -> None:
    """The four ratified cases: refuse over a 0.5 file, --force overrides, v3 over v3 is fine, empty project writes."""
    default_path = tmp_path / "gruff-baseline.json"
    legacy_bytes = json.dumps({"schemaVersion": "gruff-py.baseline.v1", "findings": []}).encode("utf-8")

    # An empty project has nothing to protect.
    require_overwritable_default_path(tmp_path, "gruff-baseline.json", force=False)

    default_path.write_bytes(legacy_bytes)
    with pytest.raises(BaselineError, match="--force"):
        require_overwritable_default_path(tmp_path, "gruff-baseline.json", force=False)
    # The refusal is not a write: the retreat copy is exactly as the user left it.
    assert default_path.read_bytes() == legacy_bytes
    # The destructive case stays available and stays explicit.
    require_overwritable_default_path(tmp_path, "gruff-baseline.json", force=True)

    # Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[_finding()])
    require_overwritable_default_path(tmp_path, "gruff-baseline.json", force=False)


def test_a_written_baseline_carries_no_sentinel(tmp_path: Path) -> None:
    """Proof C2's artifact half: a generated baseline holds no sensitive material in any form.

    A file a team commits and shares must not leak the secret it was counting, in raw, partial, hashed or encoded form.
    """
    # A synthetic AWS-shaped literal, not a live credential; it exists to be searched for.
    sentinel = "AKIA" + "IOSFODNN7EXAMPLE"
    secret = _finding(
        rule_id="sensitive-data.aws-access-key",
        pillar=Pillar.SENSITIVE_DATA,
        symbol=None,
        message=f"possible AWS access key {sentinel} in a literal",
    )
    generate_baseline(project_root=tmp_path, path="gruff-baseline.json", findings=[secret])
    written = (tmp_path / "gruff-baseline.json").read_text(encoding="utf-8")

    for name, form in _sentinel_forms(sentinel).items():
        assert form not in written, f"the written baseline carries the {name} form of the sentinel"
    # What it does carry is a count, which is what makes the secret auditable without naming it.
    assert '"sensitive-data.aws-access-key": 1' in written


def _sentinel_forms(sentinel: str) -> dict[str, str]:
    """Return every shape a leaked secret could take in an artifact."""
    return {
        "raw": sentinel,
        "partial": sentinel[:8],
        "hashed": hashlib.sha256(sentinel.encode("utf-8")).hexdigest(),
        "encoded": base64.b64encode(sentinel.encode("utf-8")).decode("ascii"),
    }


def _write_legacy_input(tmp_path: Path) -> bytes:
    """Stage the 0.5 baseline a migration reads, and hand back its bytes for the byte-for-byte comparison after."""
    legacy_bytes = json.dumps(
        {
            "schemaVersion": "gruff-py.baseline.v1",
            "generatedAt": "2026-08-01T00:00:00+00:00",
            "findings": [
                {
                    "fingerprint": "5b1d9c0a3e7f2648",
                    "ruleId": "docs.example",
                    "file": "src/example.py",
                    "line": 12,
                    "symbol": "example",
                    "message": "Example finding.",
                }
            ],
        },
        indent=4,
    ).encode("utf-8")
    (tmp_path / "legacy.json").write_bytes(legacy_bytes)
    return legacy_bytes


def _finding(
    *,
    rule_id: str = "docs.example",
    message: str = "Example finding.",
    symbol: str | None = "example",
    line: int | None = 12,
    pillar: Pillar = Pillar.DOCUMENTATION,
) -> Finding:
    """Build one ordinary finding; each test varies only the field whose effect on the identity it is proving."""
    return Finding(
        rule_id=rule_id,
        message=message,
        file_path="src/example.py",
        line=line,
        severity=Severity.ADVISORY,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol=symbol,
    )
