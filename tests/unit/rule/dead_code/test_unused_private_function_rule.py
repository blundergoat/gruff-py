"""Protect private-function findings across local and project scan journeys.

The fixtures model files a user scans together, including imports, registry
loads, rebinding, partial scope, and ambiguous source layouts. Local controls
keep existing private-method and dynamic exemptions visible during migration.
"""

import ast
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.dead_code.unused_private_function_rule import UnusedPrivateFunctionRule
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

_MAX_MODULE_WALKS_ACROSS_TWO_ANALYSES = 6


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Build one parsed user file with parent links for dead-code analysis.

    Args:
        source: Non-empty Python source the user asked gruff to scan.
        display_path: Project-relative file path; the default models one flat file.

    Returns:
        Parsed analysis unit ready for local or project rule dispatch; never None.
    """
    tree = ast.parse(source)
    # Parent links let the rule distinguish the user's module and class scopes.
    for parent in ast.walk(tree):
        # Every parsed child needs its lexical owner for qualified finding symbols.
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/project/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _ctx(scan_scope: str = "full-project") -> RuleContext:
    """Build the rule context for a full or partial user scan.

    Args:
        scan_scope: Full-project enables module conclusions; partial suppresses them.

    Returns:
        Enabled rule context with an empty dynamic allowlist; never None.
    """
    rule = UnusedPrivateFunctionRule()
    return RuleContext(
        project_root="/project",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
        scan_scope=scan_scope,
    )


def _project_findings(
    units: list[AnalysisUnit],
    scan_scope: str = "full-project",
) -> list[Finding]:
    """Run the registry path users reach when analysing one or more files.

    Args:
        units: Parsed files selected for the user's scan; empty means no findings.
        scan_scope: Full-project or partial evidence classification for the run.

    Returns:
        Deterministically ordered findings from this rule alone; empty when none apply.
    """
    return RuleRegistry([UnusedPrivateFunctionRule()]).analyse(units, _ctx(scan_scope))


def test_unused_private_module_function_fires():
    src = "def _helper():\n    pass\ndef main():\n    return 1\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["name"] == "_helper"


def test_local_analysis_uses_definition_from_active_rule_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule = UnusedPrivateFunctionRule()
    definition = replace(rule.definition(), default_severity=Severity.ERROR)
    monkeypatch.setattr(rule, "definition", lambda: definition)

    findings = rule.analyse(_unit("def _helper():\n    pass\n"), _ctx())

    assert len(findings) == 1
    assert findings[0].severity is Severity.ERROR


def test_used_private_function_does_not_fire():
    src = "def _helper():\n    return 1\ndef main():\n    return _helper()\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_public_function_skipped():
    src = "def helper():\n    pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_method_skipped():
    src = "class C:\n    def __init__(self):\n        pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_unused_private_method_fires():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return 2\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C._helper"


def test_used_private_method_via_self_does_not_fire():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return self._helper()\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_used_private_method_via_getattr_literal_does_not_fire():
    src = (
        "class C:\n"
        "    def _helper(self):\n        return 1\n"
        "    def main(self):\n        return getattr(self, '_helper')()\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_sibling_method_reference_does_not_hide_unused_nested_private_function() -> None:
    """Keep nested-function liveness inside its enclosing method's lexical scope."""
    source = (
        "class Service:\n"
        "    def build(self):\n"
        "        def _nested():\n"
        "            return 1\n"
        "        return 2\n"
        "    def unrelated(self):\n"
        "        return _nested\n"
    )

    findings = UnusedPrivateFunctionRule().analyse(_unit(source), _ctx())

    assert [finding.metadata["name"] for finding in findings] == ["_nested"]


def test_enclosing_method_call_keeps_nested_private_function_live() -> None:
    """Accept a nested private function called from its own lexical scope."""
    source = (
        "class Service:\n"
        "    def build(self):\n"
        "        def _nested():\n"
        "            return 1\n"
        "        return _nested()\n"
    )

    findings = UnusedPrivateFunctionRule().analyse(_unit(source), _ctx())

    assert findings == []


def test_dispatcher_prefix_suppresses_matching_private_methods_only():
    src = (
        "class C:\n"
        "    def main(self, kind):\n"
        "        return getattr(self, f'_handle_{kind}')()\n"
        "    def _handle_a(self):\n        return 1\n"
        "    def _unrelated(self):\n        return 2\n"
    )
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())

    assert [finding.metadata["name"] for finding in findings] == ["_unrelated"]


def test_in_all_skipped():
    src = "__all__ = ['_helper']\ndef _helper():\n    pass\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_protocol_method_skipped():
    src = "from typing import Protocol\nclass P(Protocol):\n    def _hook(self): ...\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_pytest_fixture_skipped():
    src = "import pytest\n@pytest.fixture\ndef _setup(): return 1\n"
    findings = UnusedPrivateFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


@pytest.mark.parametrize(
    "producer_path",
    ("src/mail/formatters.py", "mail/formatters.py"),
    ids=("src-layout", "flat-layout"),
)
def test_project_imported_and_registered_private_function_is_live(
    producer_path: str,
) -> None:
    """Keep a private function when another scanned file loads it into a registry.

    Args:
        producer_path: Src-layout or flat-layout path selected by the user.
    """
    producer = _unit(
        "def _format_failed_emails():\n    return []\n",
        producer_path,
    )
    consumer = _unit(
        "from mail.formatters import _format_failed_emails\n"
        "FAILED_EMAIL_FORMATTERS = {'default': _format_failed_emails}\n",
        "src/mail/registry.py" if producer_path.startswith("src/") else "mail/registry.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_imported_but_unused_private_function_still_fires() -> None:
    """Report dead code when a consumer imports it but never performs a load."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    import_only = _unit(
        "from pkg.helpers import _helper\n",
        "src/pkg/import_only.py",
    )

    findings = _project_findings([producer, import_only])

    assert [finding.symbol for finding in findings] == ["_helper"]
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].metadata == {
        "name": "_helper",
        "scanScope": "full-project",
        "externalReferenceCoverage": "complete",
    }


def test_project_module_alias_attribute_load_proves_liveness() -> None:
    """Recognize a user loading the function through an imported module alias."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "import pkg.helpers as helpers\nREGISTRY = {'helper': helpers._helper}\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_relative_import_load_proves_liveness() -> None:
    """Resolve a sibling relative import without assuming the user's source root."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from .helpers import _helper\nREGISTRY = {'helper': _helper}\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_relative_import_escaping_the_scan_root_does_not_crash() -> None:
    """Dots consuming the whole path resolve to nothing instead of raising.

    ``from .. import sys`` one directory below the scan root leaves the scanned
    set. Resolving it built an empty ``PurePosixPath('.')`` and ``with_suffix``
    raised ``ValueError``, aborting the whole run with a traceback and no report
    - reproduced on the bandit corpus repo, whose ``examples/imports-from.py``
    carries exactly this import.
    """
    producer = _unit("def _helper():\n    return 1\n", "pkg/helpers.py")
    escaping_consumer = _unit("from .. import sys\n", "pkg/imports_from.py")

    findings = _project_findings([producer, escaping_consumer])

    assert [finding.symbol for finding in findings] == ["_helper"]


def test_project_class_load_before_later_binding_uses_outer_import() -> None:
    """A later class attribute does not retroactively shadow an earlier load."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "class Registry:\n"
        "    CALLBACK = _helper\n"
        "    _helper = None\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_class_binding_before_load_shadows_outer_import() -> None:
    """A class attribute already assigned at the load site remains authoritative."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "class Registry:\n"
        "    _helper = None\n"
        "    CALLBACK = _helper\n",
        "src/pkg/consumer.py",
    )

    assert [finding.symbol for finding in _project_findings([producer, consumer])] == ["_helper"]


def test_project_function_default_uses_enclosing_import_binding() -> None:
    """Definition defaults execute before a same-named function local exists."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "def consume(callback=_helper):\n"
        "    _helper = None\n"
        "    return callback\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_package_attribute_precedes_same_named_child_module() -> None:
    """Resolve an existing package function before a scanned child module."""
    package = _unit("def _helper():\n    return 1\n", "pkg/__init__.py")
    child_module = _unit("VALUE = 1\n", "pkg/_helper.py")
    consumer = _unit(
        "from pkg import _helper\nCALLBACK = _helper\n",
        "consumer.py",
    )

    assert _project_findings([package, child_module, consumer]) == []


def test_project_leftmost_comprehension_iterable_uses_enclosing_import() -> None:
    """The first iterable evaluates before its same-named target is bound."""
    producer = _unit("def _helper():\n    return []\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\nVALUES = [_helper for _helper in _helper()]\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_comprehension_target_shadows_outer_import_in_element() -> None:
    """A target load inside the comprehension body does not use the import."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\nVALUES = [_helper for _helper in values]\n",
        "src/pkg/consumer.py",
    )

    assert [finding.symbol for finding in _project_findings([producer, consumer])] == ["_helper"]


def test_project_rebound_import_does_not_prove_original_liveness() -> None:
    """Keep the finding when user code replaces an import before loading it."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n_helper = lambda: 2\nREGISTRY = {'helper': _helper}\n",
        "src/pkg/consumer.py",
    )

    assert [finding.symbol for finding in _project_findings([producer, consumer])] == ["_helper"]


def test_project_ambiguous_module_paths_never_suppress_findings() -> None:
    """Retain LOW-confidence findings when one import maps to duplicate modules."""
    src_producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    vendor_producer = _unit("def _helper():\n    return 2\n", "vendor/pkg/helpers.py")
    consumer = _unit(
        "import pkg.helpers as helpers\nREGISTRY = {'helper': helpers._helper}\n",
        "src/pkg/consumer.py",
    )

    findings = _project_findings([src_producer, vendor_producer, consumer])

    assert [finding.file_path for finding in findings] == [
        "src/pkg/helpers.py",
        "vendor/pkg/helpers.py",
    ]
    assert {finding.confidence for finding in findings} == {Confidence.LOW}
    assert {finding.metadata["externalReferenceCoverage"] for finding in findings} == {"ambiguous"}


def test_project_partial_scan_suppresses_module_finding_but_keeps_private_method() -> None:
    """Avoid deletion advice on a narrow file while retaining class-local evidence."""
    unit = _unit(
        "def _module_helper():\n"
        "    return 1\n\n"
        "class Service:\n"
        "    def _method_helper(self):\n"
        "        return 2\n"
        "    def run(self):\n"
        "        return 3\n",
        "src/pkg/service.py",
    )

    findings = _project_findings([unit], scan_scope="partial-scope")

    assert [finding.symbol for finding in findings] == ["Service._method_helper"]
    assert findings[0].metadata == {"name": "_method_helper"}


def test_project_full_scan_preserves_unreferenced_finding_identity() -> None:
    """Add coverage metadata without changing the user's baseline identities."""
    findings = _project_findings([_unit("def _helper():\n    return 1\n")])

    assert len(findings) == 1
    assert findings[0].fingerprint() == "b21129ce5e96631b"
    assert findings[0].stable_identity() == "03f9a5e4a00227ca"
    assert findings[0].metadata == {
        "name": "_helper",
        "scanScope": "full-project",
        "externalReferenceCoverage": "complete",
    }


def test_project_producer_all_export_remains_exempt() -> None:
    """Preserve the user's explicit private export exemption after migration."""
    producer = _unit(
        "__all__ = ['_helper']\ndef _helper():\n    return 1\n",
        "src/pkg/helpers.py",
    )

    assert _project_findings([producer]) == []


def test_project_index_walks_each_generated_module_a_bounded_number_of_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep project indexing linear as users add more scanned modules.

    Args:
        monkeypatch: Fixture that counts whole-module AST walks during the scan.
    """
    rule = UnusedPrivateFunctionRule()
    assert isinstance(rule, ProjectRuleProtocol)
    # Each generated module represents one additional file in the user's project.
    units = [
        _unit(
            f"def _helper_{module_index}():\n    return {module_index}\n",
            f"src/pkg/module_{module_index}.py",
        )
        for module_index in range(40)
    ]
    unit_tree_ids = {id(unit.tree) for unit in units}
    module_walk_counts: Counter[int] = Counter()
    original_walk = ast.walk

    def counted_walk(root: ast.AST) -> Iterator[ast.AST]:
        """Count whole user-module walks while preserving normal AST iteration.

        Args:
            root: AST root requested by the rule; never None.

        Returns:
            Original iterator over the root and descendants.
        """
        # Only whole-module passes measure index growth; candidate subtrees are local work.
        if id(root) in unit_tree_ids:
            module_walk_counts[id(root)] += 1
        return original_walk(root)

    monkeypatch.setattr(ast, "walk", counted_walk)

    first_findings = RuleRegistry([rule]).analyse(units, _ctx())
    second_findings = RuleRegistry([rule]).analyse(units, _ctx())

    assert len(first_findings) == len(units)
    assert [finding.to_dict() for finding in first_findings] == [
        finding.to_dict() for finding in second_findings
    ]
    assert set(module_walk_counts) == unit_tree_ids
    assert max(module_walk_counts.values()) <= _MAX_MODULE_WALKS_ACROSS_TWO_ANALYSES


def test_project_conditional_rebind_keeps_the_import_reachable() -> None:
    """A branch the user may skip cannot prove the imported producer is unused."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "if use_local:\n"
        "    _helper = None\n"
        "REGISTRY = {'helper': _helper}\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_global_declaration_keeps_the_module_import_visible() -> None:
    """A ``global`` store rebinds the module name instead of shadowing it locally."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "def swap():\n"
        "    global _helper\n"
        "    callback = _helper\n"
        "    _helper = None\n"
        "    return callback\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []


def test_project_class_except_target_does_not_shadow_a_later_load() -> None:
    """Python deletes an ``except`` target, so a later class load sees the import."""
    producer = _unit("def _helper():\n    return 1\n", "src/pkg/helpers.py")
    consumer = _unit(
        "from pkg.helpers import _helper\n"
        "class Registry:\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as _helper:\n"
        "        pass\n"
        "    CALLBACK = _helper\n",
        "src/pkg/consumer.py",
    )

    assert _project_findings([producer, consumer]) == []
