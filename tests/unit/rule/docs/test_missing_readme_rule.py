from pathlib import Path

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.missing_readme_rule import MissingReadmeRule
from gruffpy.rule.registry import RuleRegistry
from tests.unit.rule.docs._helpers import make_unit


def _ctx(project_root: Path) -> RuleContext:
    """Build a rule context from the registry defaults at project_root.

    Args:
        project_root: Directory the rule checks for a README.

    Returns:
        A context that directs the README rule to the supplied project root.
    """
    return RuleContext(
        project_root=str(project_root),
        config=AnalysisConfig.from_registry(RuleRegistry.defaults()),
    )


def test_readme_md_present_emits_nothing(tmp_path: Path):
    """Report nothing when the project root holds a ``README.md``.

    Args:
        tmp_path: Temporary project root where the test writes README.md.

    Returns:
        None. Writes README.md and checks that the rule emits no finding.
    """
    (tmp_path / "README.md").write_text("# Project\n")
    src = "def f():\n    pass\n"
    assert MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path)) == []


def test_readme_rst_present_emits_nothing(tmp_path: Path):
    """Report nothing when the project root holds a ``README.rst``.

    Args:
        tmp_path: Temporary project root where the test writes README.rst.

    Returns:
        None. Writes README.rst and checks that the rule emits no finding.
    """
    (tmp_path / "README.rst").write_text("Project\n=======\n")
    src = "def f():\n    pass\n"
    assert MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path)) == []


def test_no_readme_emits(tmp_path: Path):
    """Report one missing-README finding when the project root has no README.

    Args:
        tmp_path: Empty project root.

    Returns:
        None. Checks that the empty project root produces one docs.missing-readme finding.
    """
    src = "def f():\n    pass\n"
    findings = MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "docs.missing-readme"


def test_finding_path_is_project_relative(tmp_path: Path) -> None:
    """Name ``README.md`` relative to the root, so two checkouts of one project share the finding's identity.

    Args:
        tmp_path: Temporary parent in which the test creates two checkout directories.

    Returns:
        None. Creates two checkout directories and checks that their findings have the same relative path and fingerprint.
    """
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    src = "def f():\n    pass\n"

    findings = [MissingReadmeRule().analyse(make_unit(src), _ctx(root))[0] for root in (first, second)]

    assert [finding.file_path for finding in findings] == ["README.md", "README.md"]
    assert findings[0].fingerprint() == findings[1].fingerprint()


def test_same_finding_per_unit_for_dedup(tmp_path: Path):
    """Give the missing-README findings from two units one fingerprint.

    Args:
        tmp_path: Empty project root shared by both units.

    Returns:
        None. Checks that each unit produces one finding and that the two fingerprints match.
    """
    # A missing README is reported for the project root even when the rule analyzes separate source units.
    # The registry compares message and metadata as well as the fields used to compute the fingerprint.
    # This test covers only the identity fields shared by fingerprinting and registry deduplication.
    rule = MissingReadmeRule()
    a = rule.analyse(make_unit("def f(): pass\n", "a.py"), _ctx(tmp_path))
    b = rule.analyse(make_unit("def g(): pass\n", "b.py"), _ctx(tmp_path))
    assert len(a) == 1 and len(b) == 1
    assert a[0].fingerprint() == b[0].fingerprint()
