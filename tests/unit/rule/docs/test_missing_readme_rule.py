from pathlib import Path

from gruff.config.analysis_config import AnalysisConfig
from gruff.rule.context import RuleContext
from gruff.rule.docs.missing_readme_rule import MissingReadmeRule
from gruff.rule.registry import RuleRegistry
from tests.unit.rule.docs._helpers import make_unit


def _ctx(project_root: Path) -> RuleContext:
    return RuleContext(
        project_root=str(project_root),
        config=AnalysisConfig.from_registry(RuleRegistry.defaults()),
    )


def test_readme_md_present_emits_nothing(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Project\n")
    src = "def f():\n    pass\n"
    assert MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path)) == []


def test_readme_rst_present_emits_nothing(tmp_path: Path):
    (tmp_path / "README.rst").write_text("Project\n=======\n")
    src = "def f():\n    pass\n"
    assert MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path)) == []


def test_no_readme_emits(tmp_path: Path):
    src = "def f():\n    pass\n"
    findings = MissingReadmeRule().analyse(make_unit(src), _ctx(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "docs.missing-readme"


def test_same_finding_per_unit_for_dedup(tmp_path: Path):
    # Two units with the same project root must produce byte-identical findings
    # so the registry's dedup collapses them to one. We approximate that by
    # asserting the fingerprints match.
    rule = MissingReadmeRule()
    a = rule.analyse(make_unit("def f(): pass\n", "a.py"), _ctx(tmp_path))
    b = rule.analyse(make_unit("def g(): pass\n", "b.py"), _ctx(tmp_path))
    assert len(a) == 1 and len(b) == 1
    assert a[0].fingerprint() == b[0].fingerprint()
