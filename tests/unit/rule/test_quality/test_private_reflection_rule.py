from gruffpy.rule.test_quality.private_reflection_rule import PrivateReflectionRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_private_attribute_access_emits():
    src = "def test_foo():\n    assert obj._private == 1\n"
    findings = PrivateReflectionRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["attribute"] == "_private"


def test_dunder_access_skipped():
    src = "def test_foo():\n    assert obj.__class__.__name__ == 'X'\n"
    assert PrivateReflectionRule().analyse(make_unit(src), default_ctx()) == []


def test_self_private_access_skipped():
    src = "class TestX:\n    def test_a(self):\n        assert self._helper == 1\n"
    assert PrivateReflectionRule().analyse(make_unit(src), default_ctx()) == []
