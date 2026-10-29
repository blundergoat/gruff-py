import ast
from dataclasses import replace
from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.pillar import Pillar
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.catalog import (
    BUILTIN_RULES,
    catalog_definitions,
    documentation_for_rule,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_RULE_ROOT = _PROJECT_ROOT / "src" / "gruffpy" / "rule"

_PREFIXES_BY_PILLAR = {
    Pillar.SIZE: ("size.",),
    Pillar.COMPLEXITY: ("complexity.",),
    Pillar.CORRECTNESS: ("correctness.",),
    Pillar.MAINTAINABILITY: ("complexity.", "maintainability."),
    Pillar.DEAD_CODE: ("dead-code.", "waste."),
    Pillar.MODERNISATION: ("modernisation.",),
    Pillar.NAMING: ("naming.",),
    Pillar.DOCUMENTATION: ("docs.",),
    Pillar.SECURITY: ("security.",),
    Pillar.SENSITIVE_DATA: ("sensitive-data.",),
    Pillar.TEST_QUALITY: ("test-quality.",),
    Pillar.DESIGN: ("design.",),
}

_FORMULA_RULES = {
    "complexity.cyclomatic",
}

_ALL_DEFINITIONS = catalog_definitions()

_M02_OPT_IN_CASES = (
    ("complexity.cyclomatic", "def f(x):\n" + "\n".join(f"    if x == {i}: return {i}" for i in range(25)) + "\n", "x.py"),
    ("security.dangerous-function-call", "eval(user_input)\n", "x.py"),
    (
        "security.header-injection",
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def view():\n"
        "    response = make_response('hi')\n"
        "    response.headers[request.args['name']] = 'value'\n"
        "    return response\n",
        "x.py",
    ),
    ("security.unsafe-yaml-load", "import yaml\nyaml.unsafe_load(data)\n", "x.py"),
    ("security.variable-import", "import importlib\nname = request.args['mod']\nimportlib.import_module(name)\n", "x.py"),
    ("security.xxe", "import xml.etree.ElementTree as ET\ntree = ET.parse('x.xml')\n", "x.py"),
    ("sensitive-data.database-url-password", "DATABASE_URL = 'postgresql://admin:" + "s3cret!" + "@db.example.com/myapp'\n", "x.py"),
    ("test-quality.no-assertions", "def test_foo():\n    x = 1\n", "test_x.py"),
    ("test-quality.sut-not-called", "def test_foo():\n    assert True\n", "test_x.py"),
)


@pytest.mark.parametrize(("rule_id", "source", "display_path"), _M02_OPT_IN_CASES, ids=[case[0] for case in _M02_OPT_IN_CASES])
def test_m02_opt_in_rules_require_configuration_to_emit(rule_id: str, source: str, display_path: str) -> None:
    """Keep each accepted opt-in rule quiet until its existing positive case is enabled.

    Args:
        rule_id: Rule kept opt-in by M02's accepted table.
        source: Positive input retained from the rule's detector tests.
        display_path: Production or collected-test scope required by the detector.
    """
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # Production parsing supplies AST parent links.
    unit = AnalysisUnit(
        file=SourceFile(absolute_path="/" + display_path, display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )

    assert config.rule_settings(rule_id).enabled is False
    assert not any(finding.rule_id == rule_id for finding in registry.analyse([unit], RuleContext(project_root="/", config=config)))

    enabled = config.with_rule_settings(rule_id, replace(config.rule_settings(rule_id), enabled=True))
    findings = registry.analyse([unit], RuleContext(project_root="/", config=enabled))
    assert any(finding.rule_id == rule_id for finding in findings)


def test_catalog_entries_are_importable_and_unique() -> None:
    definitions = catalog_definitions()
    ids = [definition.id for definition in definitions]

    assert len(definitions) == len(BUILTIN_RULES)
    assert len(ids) == len(set(ids))
    assert ids == [entry.create().definition().id for entry in BUILTIN_RULES]


def test_registry_defaults_consumes_catalog_entries() -> None:
    catalog_ids = {definition.id for definition in catalog_definitions()}
    registry_ids = {rule.definition().id for rule in RuleRegistry.defaults().all()}

    assert registry_ids == catalog_ids
    assert AnalysisConfig.from_registry(RuleRegistry.defaults()).rules.keys() == registry_ids


@pytest.mark.parametrize("definition", _ALL_DEFINITIONS, ids=lambda d: d.id)
def test_rule_id_matches_pillar_prefix_convention(definition: RuleDefinition) -> None:
    prefixes = _PREFIXES_BY_PILLAR[definition.pillar]
    assert definition.id.startswith(prefixes)


def test_no_concrete_rule_class_is_omitted_from_catalog() -> None:
    catalog_classes = {f"{type(entry.create()).__module__}.{type(entry.create()).__name__}" for entry in BUILTIN_RULES}
    concrete_classes = set(_concrete_rule_class_paths())

    assert concrete_classes == catalog_classes


_DETERMINISM_FIXTURE = '''
class LongClassWithBadNamingAndDeadCode:
    """Mixed-pillar fixture exercising naming, size, dead-code, and complexity."""

    def methodWithCamelCase(self, a, b, c, d, e, f, g, h):
        x = 1
        y = 2
        z = 3
        for i in range(10):
            if i > 5:
                if i < 8:
                    if i == 7:
                        print(i)
        return a + b + c + d + e + f + g + h + x + y + z


def _unused_private_helper():
    pass
'''


def test_registry_analyse_is_deterministic_across_runs() -> None:
    """Running the full registry on the same source twice produces identical fingerprints."""
    tree_a = ast.parse(_DETERMINISM_FIXTURE)
    tree_b = ast.parse(_DETERMINISM_FIXTURE)
    file = SourceFile(absolute_path="/d.py", display_path="d.py", type="python")
    unit_a = AnalysisUnit(file=file, source=_DETERMINISM_FIXTURE, tree=tree_a)
    unit_b = AnalysisUnit(file=file, source=_DETERMINISM_FIXTURE, tree=tree_b)
    ctx = RuleContext(project_root="/", config=AnalysisConfig.from_registry(RuleRegistry.defaults()))
    registry = RuleRegistry.defaults()
    a = registry.analyse([unit_a], ctx)
    b = registry.analyse([unit_b], ctx)
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]


@pytest.mark.parametrize("definition", _ALL_DEFINITIONS, ids=lambda d: d.id)
def test_builtin_rule_has_required_docs_metadata(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.rationale
    assert docs.fix_guidance
    assert docs.bad_example
    assert docs.good_example
    assert docs.confidence_rationale


def test_medium_and_low_confidence_rules_publish_false_positive_guidance() -> None:
    """Every heuristic rule must tell a user where it misfires and what to do instead.

    A medium or low confidence rule will be wrong sometimes, so shipping one without
    ``falsePositiveShapes`` leaves a user with a finding they cannot judge. The two passes below
    separate the two ways that fails: a rule carrying no shapes at all, and a rule carrying a shape
    whose text or mitigation is blank, which reads as guidance but answers nothing.

    Returns:
        None; either list being non-empty raises an assertion naming the offending rule ids.
    """
    heuristic_definitions = [definition for definition in _ALL_DEFINITIONS if definition.confidence in {Confidence.MEDIUM, Confidence.LOW}]
    missing = [definition.id for definition in heuristic_definitions if not documentation_for_rule(definition.id).false_positive_shapes]
    incomplete = [
        definition.id
        for definition in heuristic_definitions
        for shape in documentation_for_rule(definition.id).false_positive_shapes
        if not shape.shape.strip() or not shape.mitigation.strip()
    ]

    assert missing == []
    assert incomplete == []


_METRIC_DEFINITIONS = [d for d in _ALL_DEFINITIONS if d.id in _FORMULA_RULES]
_NON_METRIC_DEFINITIONS = [d for d in _ALL_DEFINITIONS if d.id not in _FORMULA_RULES]


@pytest.mark.parametrize("definition", _METRIC_DEFINITIONS, ids=lambda d: d.id)
def test_metric_rule_publishes_formula_provenance(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.formula_provenance


@pytest.mark.parametrize("definition", _NON_METRIC_DEFINITIONS, ids=lambda d: d.id)
def test_non_metric_rule_has_no_formula_provenance(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.formula_provenance == ""


_SIZE_OR_COMPLEXITY_PILLARS = {Pillar.SIZE, Pillar.COMPLEXITY, Pillar.MAINTAINABILITY}
_SIZE_AND_COMPLEXITY_DEFINITIONS = [d for d in _ALL_DEFINITIONS if d.pillar in _SIZE_OR_COMPLEXITY_PILLARS]


@pytest.mark.parametrize("definition", _SIZE_AND_COMPLEXITY_DEFINITIONS, ids=lambda d: d.id)
def test_size_and_complexity_threshold_docs_publish_standard_metadata_contract(
    definition: RuleDefinition,
) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.threshold_metadata_keys == (
        "measuredValue",
        "threshold",
        "thresholdDirection",
        "thresholdType",
    )
    assert docs.threshold_direction in {"above", "below"}


def test_selected_security_rules_publish_taxonomy_metadata() -> None:
    docs = documentation_for_rule("security.django-raw-sql")
    assert docs.security_metadata["cwe"] == ["CWE-89"]
    assert docs.to_payload()["security"]["securitySeverity"] == "high"

    yaml_docs = documentation_for_rule("security.unsafe-yaml-load")
    assert yaml_docs.security_metadata["cwe"] == ["CWE-502"]


def _concrete_rule_class_paths() -> list[str]:
    classes: list[str] = []
    for path in sorted(_RULE_ROOT.rglob("*_rule.py")):
        if path.name == "project_rule.py":
            continue
        module_name = "gruffpy.rule." + ".".join(path.relative_to(_RULE_ROOT).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and _looks_like_rule_class(node):
                classes.append(f"{module_name}.{node.name}")
    return sorted(classes)


def _looks_like_rule_class(cls: ast.ClassDef) -> bool:
    methods = {node.name for node in cls.body if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)}
    return "definition" in methods and bool({"analyse", "analyse_project"} & methods)


@pytest.mark.parametrize(
    "source",
    (
        'msg = "Hello, {}!".format(name)\n',
        'msg = "Hello, {name}!".format(name=name)\n',
        'msg = "Hello".format()\n',
        'template = "Hello, {}!"\nmsg = template.format(name)\n',
        'msg = f"Hello, {name}!"\n',
        'msg = "hello".upper()\n',
        "msg = (1).bit_length()\n",
        'a = "x={}".format(x)\nb = "y={}".format(y)\n',
    ),
    ids=("positional", "keyword", "no-arguments", "variable-template", "f-string", "other-method", "non-string", "two-calls"),
)
def test_retired_f_string_rule_never_runs(source: str) -> None:
    """Keep the retired detector absent even when its former setting is enabled.

    Args:
        source: A preserved positive or negative case from the retired rule's tests.
    """
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    config.rules["modernisation.f-string-candidate"] = RuleSettings(enabled=True)
    unit = AnalysisUnit(
        file=SourceFile(absolute_path="/pilot.py", display_path="pilot.py", type="python"),
        source=source,
        tree=ast.parse(source),
    )
    findings = registry.analyse([unit], RuleContext(project_root="/", config=config))
    assert "modernisation.f-string-candidate" not in {rule.definition().id for rule in registry.all()}
    assert not any(finding.rule_id == "modernisation.f-string-candidate" for finding in findings)


@pytest.mark.parametrize(
    ("rule_id", "source", "display_path"),
    (
        (
            "waste.commented-out-code",
            ("# x = 1\n"),
            "users.py",
        ),
        (
            "waste.empty-class",
            ("class C:\n    pass\n"),
            "users.py",
        ),
        (
            "waste.one-line-function",
            ("def foo(x):\n    return bar(x)\n"),
            "users.py",
        ),
        (
            "waste.redundant-variable",
            ("def f():\n    x = 1 + 2\n    return x\n"),
            "users.py",
        ),
        (
            "waste.unused-import",
            ("import os\n"),
            "users.py",
        ),
        (
            "test-quality.conditional-logic",
            ("def test_foo():\n    if cond:\n        assert True\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.eager-test",
            (
                "def test_eager_asserts_many_values():\n    value = exercise()\n    assert value =="
                " 1\n    assert value == 1\n    assert value == 1\n    assert value == 1\n    assert "
                "value == 1\n    assert value == 1\n"
            ),
            "tests/test_retired.py",
        ),
        (
            "test-quality.exception-type-only",
            ("def test_wide_exception_without_match():\n    with pytest.raises(Exception):\n        exercise()\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.extends-production-class",
            ("class TestService(Service):\n    def test_x(self):\n        assert True\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.loop-in-test",
            ("def test_foo():\n    for i in range(3):\n        assert i >= 0\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.magic-number-assertion",
            ("def test_foo():\n    assert result == 17\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.mock-without-expectation",
            (
                "def test_mock_without_expectation_case():\n    collaborator = Mock()\n    exercise"
                "(collaborator)\n    assert collaborator is not None\n"
            ),
            "tests/test_retired.py",
        ),
        (
            "test-quality.multiple-aaa-cycles",
            (
                "def test_foo():\n    first = exercise()\n    assert first == 1\n    second = exerci"
                "se()\n    assert second == 2\n    third = exercise()\n    assert third == 3\n"
            ),
            "tests/test_retired.py",
        ),
        (
            "test-quality.mystery-guest",
            ("import requests\ndef test_fetch():\n    assert requests.get('http://example.test').ok\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.parametrize-annotation",
            ('@pytest.mark.parametrize("value", [1, 1, 1])\ndef test_parametrize_without_case_ids(value):\n    assert exercise(value) == value\n'),
            "tests/test_retired.py",
        ),
        (
            "test-quality.skipped-without-reason",
            ("import pytest\n@pytest.mark.skip\ndef test_foo():\n    assert True\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.sleep-in-test",
            ("import time\ndef test_foo():\n    time.sleep(1)\n    assert True\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.tautological-type-assertion",
            ("def test_value():\n    value = object()\n    assert isinstance(value, type(value))\n"),
            "tests/test_retired.py",
        ),
        (
            "test-quality.trivial-snapshot",
            ('def test_trivial_snapshot_case_is_detected():\n    assert exercise() == ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]\n'),
            "tests/test_retired.py",
        ),
        (
            "docs.useless-docstring",
            ('def process(value):\n    """Process the value."""\n    return value\n'),
            "users.py",
        ),
        (
            "naming.boolean-prefix",
            ("def status(x) -> bool:\n    return True\n"),
            "users.py",
        ),
        (
            "naming.confusing-name",
            ("class Handler:\n    pass\n"),
            "users.py",
        ),
        (
            "naming.hungarian-notation",
            ("i_count = 0\n"),
            "users.py",
        ),
        (
            "naming.module-name-mismatch",
            ("class UserService:\n    pass\n"),
            "users.py",
        ),
        (
            "security.unsanitized-markdown-interpolation",
            ('def render(raw_label, raw_url, condition=True):\n    return f"""[{raw_label}]({raw_url})"""\n'),
            "users.py",
        ),
        (
            "sensitive-data.pii-test-fixture",
            ("user_email = 'jane.doe" + "@" + "gmail.com'\n"),
            "tests/test_users.py",
        ),
        (
            "complexity.halstead-volume",
            (
                "def f():\n    if a0 > b0:\n        x = a0 + b0\n    else:\n        x = a0 - b0\n    i"
                "f a1 > b1:\n        x = a1 + b1\n    else:\n        x = a1 - b1\n    if a2 > b2:\n   "
                "     x = a2 + b2\n    else:\n        x = a2 - b2\n    if a3 > b3:\n        x = a3 + "
                "b3\n    else:\n        x = a3 - b3\n    if a4 > b4:\n        x = a4 + b4\n    else:\n "
                "       x = a4 - b4\n    if a5 > b5:\n        x = a5 + b5\n    else:\n        x = a5 "
                "- b5\n    if a6 > b6:\n        x = a6 + b6\n    else:\n        x = a6 - b6\n    if a7"
                " > b7:\n        x = a7 + b7\n    else:\n        x = a7 - b7\n    if a8 > b8:\n       "
                " x = a8 + b8\n    else:\n        x = a8 - b8\n    if a9 > b9:\n        x = a9 + b9\n "
                "   else:\n        x = a9 - b9\n    if a10 > b10:\n        x = a10 + b10\n    else:\n "
                "       x = a10 - b10\n    if a11 > b11:\n        x = a11 + b11\n    else:\n        x"
                " = a11 - b11\n    if a12 > b12:\n        x = a12 + b12\n    else:\n        x = a12 -"
                " b12\n    if a13 > b13:\n        x = a13 + b13\n    else:\n        x = a13 - b13\n   "
                " if a14 > b14:\n        x = a14 + b14\n    else:\n        x = a14 - b14\n    if a15 "
                "> b15:\n        x = a15 + b15\n    else:\n        x = a15 - b15\n    if a16 > b16:\n "
                "       x = a16 + b16\n    else:\n        x = a16 - b16\n    if a17 > b17:\n        x"
                " = a17 + b17\n    else:\n        x = a17 - b17\n    if a18 > b18:\n        x = a18 +"
                " b18\n    else:\n        x = a18 - b18\n    if a19 > b19:\n        x = a19 + b19\n   "
                " else:\n        x = a19 - b19\n    if a20 > b20:\n        x = a20 + b20\n    else:\n "
                "       x = a20 - b20\n    if a21 > b21:\n        x = a21 + b21\n    else:\n        x"
                " = a21 - b21\n    if a22 > b22:\n        x = a22 + b22\n    else:\n        x = a22 -"
                " b22\n    if a23 > b23:\n        x = a23 + b23\n    else:\n        x = a23 - b23\n   "
                " if a24 > b24:\n        x = a24 + b24\n    else:\n        x = a24 - b24\n    if a25 "
                "> b25:\n        x = a25 + b25\n    else:\n        x = a25 - b25\n    if a26 > b26:\n "
                "       x = a26 + b26\n    else:\n        x = a26 - b26\n    if a27 > b27:\n        x"
                " = a27 + b27\n    else:\n        x = a27 - b27\n    if a28 > b28:\n        x = a28 +"
                " b28\n    else:\n        x = a28 - b28\n    if a29 > b29:\n        x = a29 + b29\n   "
                " else:\n        x = a29 - b29\n    if a30 > b30:\n        x = a30 + b30\n    else:\n "
                "       x = a30 - b30\n    if a31 > b31:\n        x = a31 + b31\n    else:\n        x"
                " = a31 - b31\n    if a32 > b32:\n        x = a32 + b32\n    else:\n        x = a32 -"
                " b32\n    if a33 > b33:\n        x = a33 + b33\n    else:\n        x = a33 - b33\n   "
                " if a34 > b34:\n        x = a34 + b34\n    else:\n        x = a34 - b34\n    if a35 "
                "> b35:\n        x = a35 + b35\n    else:\n        x = a35 - b35\n    if a36 > b36:\n "
                "       x = a36 + b36\n    else:\n        x = a36 - b36\n    if a37 > b37:\n        x"
                " = a37 + b37\n    else:\n        x = a37 - b37\n    if a38 > b38:\n        x = a38 +"
                " b38\n    else:\n        x = a38 - b38\n    if a39 > b39:\n        x = a39 + b39\n   "
                " else:\n        x = a39 - b39\n    return x\n"
            ),
            "users.py",
        ),
        (
            "complexity.maintainability-index",
            (
                "def f():\n    if a0 > b0:\n        x = a0 + b0\n    else:\n        x = a0 - b0\n    i"
                "f a1 > b1:\n        x = a1 + b1\n    else:\n        x = a1 - b1\n    if a2 > b2:\n   "
                "     x = a2 + b2\n    else:\n        x = a2 - b2\n    if a3 > b3:\n        x = a3 + "
                "b3\n    else:\n        x = a3 - b3\n    if a4 > b4:\n        x = a4 + b4\n    else:\n "
                "       x = a4 - b4\n    if a5 > b5:\n        x = a5 + b5\n    else:\n        x = a5 "
                "- b5\n    if a6 > b6:\n        x = a6 + b6\n    else:\n        x = a6 - b6\n    if a7"
                " > b7:\n        x = a7 + b7\n    else:\n        x = a7 - b7\n    if a8 > b8:\n       "
                " x = a8 + b8\n    else:\n        x = a8 - b8\n    if a9 > b9:\n        x = a9 + b9\n "
                "   else:\n        x = a9 - b9\n    if a10 > b10:\n        x = a10 + b10\n    else:\n "
                "       x = a10 - b10\n    if a11 > b11:\n        x = a11 + b11\n    else:\n        x"
                " = a11 - b11\n    if a12 > b12:\n        x = a12 + b12\n    else:\n        x = a12 -"
                " b12\n    if a13 > b13:\n        x = a13 + b13\n    else:\n        x = a13 - b13\n   "
                " if a14 > b14:\n        x = a14 + b14\n    else:\n        x = a14 - b14\n    if a15 "
                "> b15:\n        x = a15 + b15\n    else:\n        x = a15 - b15\n    if a16 > b16:\n "
                "       x = a16 + b16\n    else:\n        x = a16 - b16\n    if a17 > b17:\n        x"
                " = a17 + b17\n    else:\n        x = a17 - b17\n    if a18 > b18:\n        x = a18 +"
                " b18\n    else:\n        x = a18 - b18\n    if a19 > b19:\n        x = a19 + b19\n   "
                " else:\n        x = a19 - b19\n    if a20 > b20:\n        x = a20 + b20\n    else:\n "
                "       x = a20 - b20\n    if a21 > b21:\n        x = a21 + b21\n    else:\n        x"
                " = a21 - b21\n    if a22 > b22:\n        x = a22 + b22\n    else:\n        x = a22 -"
                " b22\n    if a23 > b23:\n        x = a23 + b23\n    else:\n        x = a23 - b23\n   "
                " if a24 > b24:\n        x = a24 + b24\n    else:\n        x = a24 - b24\n    if a25 "
                "> b25:\n        x = a25 + b25\n    else:\n        x = a25 - b25\n    if a26 > b26:\n "
                "       x = a26 + b26\n    else:\n        x = a26 - b26\n    if a27 > b27:\n        x"
                " = a27 + b27\n    else:\n        x = a27 - b27\n    if a28 > b28:\n        x = a28 +"
                " b28\n    else:\n        x = a28 - b28\n    if a29 > b29:\n        x = a29 + b29\n   "
                " else:\n        x = a29 - b29\n    if a30 > b30:\n        x = a30 + b30\n    else:\n "
                "       x = a30 - b30\n    if a31 > b31:\n        x = a31 + b31\n    else:\n        x"
                " = a31 - b31\n    if a32 > b32:\n        x = a32 + b32\n    else:\n        x = a32 -"
                " b32\n    if a33 > b33:\n        x = a33 + b33\n    else:\n        x = a33 - b33\n   "
                " if a34 > b34:\n        x = a34 + b34\n    else:\n        x = a34 - b34\n    if a35 "
                "> b35:\n        x = a35 + b35\n    else:\n        x = a35 - b35\n    if a36 > b36:\n "
                "       x = a36 + b36\n    else:\n        x = a36 - b36\n    if a37 > b37:\n        x"
                " = a37 + b37\n    else:\n        x = a37 - b37\n    if a38 > b38:\n        x = a38 +"
                " b38\n    else:\n        x = a38 - b38\n    if a39 > b39:\n        x = a39 + b39\n   "
                " else:\n        x = a39 - b39\n    return x\n"
            ),
            "users.py",
        ),
    ),
    ids=(
        "waste.commented-out-code",
        "waste.empty-class",
        "waste.one-line-function",
        "waste.redundant-variable",
        "waste.unused-import",
        "test-quality.conditional-logic",
        "test-quality.eager-test",
        "test-quality.exception-type-only",
        "test-quality.extends-production-class",
        "test-quality.loop-in-test",
        "test-quality.magic-number-assertion",
        "test-quality.mock-without-expectation",
        "test-quality.multiple-aaa-cycles",
        "test-quality.mystery-guest",
        "test-quality.parametrize-annotation",
        "test-quality.skipped-without-reason",
        "test-quality.sleep-in-test",
        "test-quality.tautological-type-assertion",
        "test-quality.trivial-snapshot",
        "docs.useless-docstring",
        "naming.boolean-prefix",
        "naming.confusing-name",
        "naming.hungarian-notation",
        "naming.module-name-mismatch",
        "security.unsanitized-markdown-interpolation",
        "sensitive-data.pii-test-fixture",
        "complexity.halstead-volume",
        "complexity.maintainability-index",
    ),
)
def test_retired_m02_rules_never_run(rule_id: str, source: str, display_path: str) -> None:
    """Keep approved retired emitters absent even with their former settings enabled.

    Args:
        rule_id: Retired rule the operator selected for deletion.
        source: Preserved positive input from that rule's former tests.
        display_path: Original production or test-file scope for the positive input.
    """
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    config.rules[rule_id] = RuleSettings(enabled=True)
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # Production parsing supplies AST parent links.
    unit = AnalysisUnit(
        file=SourceFile(absolute_path="/" + display_path, display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )
    findings = registry.analyse([unit], RuleContext(project_root="/", config=config))
    assert rule_id not in {rule.definition().id for rule in registry.all()}
    assert not any(finding.rule_id == rule_id for finding in findings)
