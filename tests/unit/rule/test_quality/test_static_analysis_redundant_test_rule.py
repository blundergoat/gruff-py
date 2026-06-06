from gruffpy.finding.confidence import Confidence
from gruffpy.finding.severity import Severity
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality.static_analysis_redundant_test_rule import (
    StaticAnalysisRedundantTestRule,
)
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit

RULE_ID = "test-quality.static-analysis-redundant-test"

_FIXTURE = (
    "import inspect\n"
    "import unittest\n\n\n"
    "class ShapeService:\n"
    "    label = 'shape'\n"
    "    code: str = 'default'\n"
    "    slug: str\n\n"
    "    def render(self) -> str:\n"
    "        return 'shape'\n\n\n"
)


def _findings(test_source):
    source = _FIXTURE + test_source
    return StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx())


def _only(test_source):
    findings = _findings(test_source)
    assert len(findings) == 1, [f.metadata.get("variant") for f in findings]
    return findings[0]


def test_inspect_isclass_flags_local_class_declaration():
    finding = _only("def test_decl():\n    assert inspect.isclass(ShapeService)\n")
    assert finding.rule_id == RULE_ID
    assert finding.metadata["variant"] == "inspect-isclass"
    assert finding.metadata["evidenceSymbol"] == "ShapeService"
    assert (
        finding.metadata["staticFact"] == "class ShapeService is declared in the same parsed file"
    )


def test_hasattr_method_flags_declared_method():
    finding = _only("def test_decl():\n    assert hasattr(ShapeService, 'render')\n")
    assert finding.metadata["variant"] == "hasattr-method"
    assert finding.metadata["evidenceSymbol"] == "ShapeService.render"
    assert finding.symbol == "test_decl"
    assert finding.message == (
        "test_decl contains a static-analysis-redundant candidate: hasattr asserts "
        "ShapeService.render, but method ShapeService.render() is declared in the same parsed file."
    )


def test_hasattr_class_attribute_flags_assignment():
    finding = _only("def test_decl():\n    assert hasattr(ShapeService, 'label')\n")
    assert finding.metadata["variant"] == "hasattr-class-attribute"
    assert finding.metadata["staticFact"] == (
        "attribute ShapeService.label is declared in the same parsed file"
    )


def test_hasattr_class_attribute_flags_annotated_assignment_with_value():
    finding = _only("def test_decl():\n    assert hasattr(ShapeService, 'code')\n")
    assert finding.metadata["variant"] == "hasattr-class-attribute"
    assert finding.metadata["evidenceSymbol"] == "ShapeService.code"


def test_callable_getattr_method_variant():
    finding = _only("def test_decl():\n    assert callable(getattr(ShapeService, 'render'))\n")
    assert finding.metadata["variant"] == "callable-getattr-method"
    assert finding.metadata["evidenceSymbol"] == "ShapeService.render"


def test_callable_attribute_method_variant():
    finding = _only("def test_decl():\n    assert callable(ShapeService.render)\n")
    assert finding.metadata["variant"] == "callable-attribute-method"


def test_unittest_asserttrue_is_detected():
    source = (
        "class TestShape(unittest.TestCase):\n"
        "    def test_decl(self):\n"
        "        self.assertTrue(hasattr(ShapeService, 'render'))\n"
    )
    finding = _only(source)
    assert finding.symbol == "TestShape.test_decl"
    assert finding.metadata["assertion"] == "self.assertTrue(hasattr(ShapeService, 'render'))"


def test_finding_carries_advisory_high_and_required_metadata_keys():
    finding = _only("def test_decl():\n    assert hasattr(ShapeService, 'render')\n")
    assert finding.severity is Severity.ADVISORY
    assert finding.confidence is Confidence.HIGH
    assert set(finding.metadata) == {
        "variant",
        "assertion",
        "staticFact",
        "evidenceSymbol",
        "candidateConfidence",
    }
    assert finding.metadata["candidateConfidence"] == "high"


def test_remediation_is_behaviour_first():
    finding = _only("def test_decl():\n    assert hasattr(ShapeService, 'render')\n")
    assert finding.remediation == (
        "Remove only the redundant assertion, or replace it with behavioral "
        "evidence that static analysis cannot prove."
    )


def test_each_redundant_assertion_emits_one_finding():
    source = (
        "def test_decl():\n"
        "    assert hasattr(ShapeService, 'render')\n"
        "    assert callable(getattr(ShapeService, 'render'))\n"
        "    assert callable(ShapeService.render)\n"
    )
    variants = sorted(f.metadata["variant"] for f in _findings(source))
    assert variants == ["callable-attribute-method", "callable-getattr-method", "hasattr-method"]


def test_nested_class_resolves_via_attribute_chain():
    source = (
        "import inspect\n\n"
        "class Outer:\n"
        "    class Inner:\n"
        "        def go(self):\n"
        "            return 1\n\n"
        "def test_decl():\n"
        "    assert inspect.isclass(Outer.Inner)\n"
    )
    findings = StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["evidenceSymbol"] == "Outer.Inner"


def test_behavioural_value_assertion_is_clean():
    source = "def test_value():\n    assert ShapeService().render() == 'shape'\n"
    assert _findings(source) == []


def test_dynamic_member_name_is_clean():
    source = "def test_value():\n    member = 'render'\n    assert hasattr(ShapeService, member)\n"
    assert _findings(source) == []


def test_instance_receiver_is_clean():
    assert _findings("def test_value(service):\n    assert hasattr(service, 'render')\n") == []


def test_imported_symbol_is_clean():
    source = (
        "def test_value():\n"
        "    from datetime import datetime\n\n"
        "    assert hasattr(datetime, 'fromisoformat')\n"
    )
    assert _findings(source) == []


def test_bare_annotation_is_clean():
    assert _findings("def test_value():\n    assert hasattr(ShapeService, 'slug')\n") == []


def test_undeclared_member_is_clean():
    assert _findings("def test_value():\n    assert hasattr(ShapeService, 'missing')\n") == []


def test_private_member_is_left_to_private_reflection():
    assert _findings("def test_value():\n    assert hasattr(ShapeService, '_secret')\n") == []


def test_callable_of_non_method_attribute_is_clean():
    assert _findings("def test_value():\n    assert callable(ShapeService.label)\n") == []


def test_negated_existence_is_clean():
    assert _findings("def test_value():\n    assert not hasattr(ShapeService, 'render')\n") == []


def test_assert_false_is_clean():
    source = (
        "class TestShape(unittest.TestCase):\n"
        "    def test_value(self):\n"
        "        self.assertFalse(hasattr(ShapeService, 'render'))\n"
    )
    assert _findings(source) == []


def test_assert_not_has_attr_is_clean():
    source = (
        "class TestShape(unittest.TestCase):\n"
        "    def test_value(self):\n"
        "        self.assertNotHasAttr(ShapeService, 'render')\n"
    )
    assert _findings(source) == []


def test_property_member_is_clean():
    source = (
        "class WithProp:\n"
        "    @property\n"
        "    def name(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    assert hasattr(WithProp, 'name')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_instance_only_attribute_is_clean():
    source = (
        "class Stateful:\n"
        "    def __init__(self):\n"
        "        self.count = 0\n\n"
        "def test_value():\n"
        "    assert hasattr(Stateful, 'count')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_setattr_injected_member_is_clean():
    source = (
        "class Dynamic:\n"
        "    pass\n\n"
        "setattr(Dynamic, 'injected', 1)\n\n"
        "def test_value():\n"
        "    assert hasattr(Dynamic, 'injected')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_conditionally_declared_class_is_clean():
    source = (
        "if True:\n"
        "    class Conditional:\n"
        "        def render(self):\n"
        "            return 'x'\n\n"
        "def test_value():\n"
        "    assert hasattr(Conditional, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_module_level_rebinding_makes_class_ambiguous():
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "Widget = None\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_module_level_function_rebinding_makes_class_ambiguous():
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def Widget():\n"
        "    return object()\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_module_level_delete_makes_class_ambiguous():
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "del Widget\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_module_level_member_rebinding_makes_method_ambiguous():
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "Widget.render = None\n\n"
        "def test_value():\n"
        "    assert callable(Widget.render)\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_nested_class_rebinding_makes_nested_class_ambiguous():
    source = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def render(self):\n"
        "            return 'x'\n"
        "    Inner = 1\n\n"
        "def test_value():\n"
        "    assert hasattr(Outer.Inner, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_test_local_rebinding_makes_class_ambiguous():
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    Widget = object()\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_star_import_disables_class_evidence():
    source = (
        "from os import *\n\n"
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_test_parameter_shadow_is_clean():
    # A fixture / parametrized argument shadows the same-file class name.
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value(Widget):\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_in_test_member_write_is_clean():
    # An in-test monkeypatch makes the member a runtime mutation, not a declaration.
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    Widget.render = lambda self: 'y'\n"
        "    assert callable(Widget.render)\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_decorated_class_is_not_trusted_evidence():
    # A class decorator can add, remove, or replace members at class creation.
    source = (
        "def strip(cls):\n"
        "    return cls\n\n"
        "@strip\n"
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_metaclass_class_is_not_trusted_evidence():
    # A metaclass can hide or synthesise members at class creation.
    source = (
        "class Meta(type):\n"
        "    pass\n\n"
        "class Widget(metaclass=Meta):\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_conditional_import_rebinding_makes_class_ambiguous():
    # A conditional module-level re-import can replace the class at runtime.
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "try:\n"
        "    from vendor import Widget\n"
        "except ImportError:\n"
        "    pass\n\n"
        "def test_value():\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_locally_shadowed_assertion_helper_is_clean():
    # The assertion helper itself is rebound in the test's local scope.
    source = (
        "class Widget:\n"
        "    def render(self):\n"
        "        return 'x'\n\n"
        "def test_value():\n"
        "    def hasattr(obj, name):\n"
        "        return False\n"
        "    assert hasattr(Widget, 'render')\n"
    )
    assert StaticAnalysisRedundantTestRule().analyse(make_unit(source), default_ctx()) == []


def test_neighbour_shapes_are_not_claimed():
    # Shapes owned by sibling test-quality rules must stay clean here.
    rule = StaticAnalysisRedundantTestRule()
    ctx = default_ctx()
    neighbour_sources = (
        "def test_value():\n    value = object()\n    assert isinstance(value, type(value))\n",
        "def test_value():\n    subject = build()\n    assert subject._secret == 1\n",
        "import pytest\n\ndef test_value():\n    with pytest.raises(Exception):\n        build()\n",
    )
    assert all(rule.analyse(make_unit(source), ctx) == [] for source in neighbour_sources)


def test_registry_exposes_rule_with_advisory_high_defaults():
    rule = RuleRegistry.defaults().get(RULE_ID)
    definition = rule.definition()
    assert definition.default_severity is Severity.ADVISORY
    assert definition.confidence is Confidence.HIGH
    assert definition.default_enabled is True
