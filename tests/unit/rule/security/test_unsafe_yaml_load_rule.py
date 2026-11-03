from gruffpy.rule.security.unsafe_yaml_load_rule import UnsafeYamlLoadRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_yaml_unsafe_load_emits():
    """Report one finding for ``yaml.unsafe_load``, with that target, the ``yaml-input`` source and the ``unsafe-yaml-loader`` sink."""
    src = "import yaml\nyaml.unsafe_load(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["target"] == "yaml.unsafe_load"
    assert findings[0].metadata["sourceLabel"] == "yaml-input"
    assert findings[0].metadata["sinkLabel"] == "unsafe-yaml-loader"


def test_yaml_load_without_loader_emits():
    """Report one finding for ``yaml.load`` without a loader."""
    src = "import yaml\nyaml.load(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_loader_emits():
    """Report one finding for ``yaml.load`` with ``Loader=yaml.Loader``."""
    src = "import yaml\nyaml.load(data, Loader=yaml.Loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_unsafe_loader_emits():
    """Report one finding for ``yaml.load`` with ``Loader=yaml.UnsafeLoader``."""
    src = "import yaml\nyaml.load(data, Loader=yaml.UnsafeLoader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_imported_alias_emits():
    """Report one finding for ``unsafe_load`` imported under another name."""
    src = "from yaml import unsafe_load as load_yaml\nload_yaml(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_safe_load_skipped():
    """Report nothing for ``yaml.safe_load``."""
    src = "import yaml\nyaml.safe_load(data)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_safe_loader_skipped():
    """Report nothing for ``yaml.load`` with ``Loader=yaml.SafeLoader``."""
    src = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_positional_safe_loader_skipped():
    """Report nothing for ``yaml.load`` with ``yaml.SafeLoader`` passed positionally."""
    src = "import yaml\nyaml.load(data, yaml.SafeLoader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_positional_unsafe_loader_emits():
    """Report one finding for ``yaml.load`` with ``yaml.Loader`` passed positionally."""
    src = "import yaml\nyaml.load(data, yaml.Loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_indirect_unsafe_loader_emits():
    """Report one finding for ``yaml.load`` with a variable bound to ``yaml.Loader``."""
    src = "import yaml\nloader = yaml.Loader\nyaml.load(data, Loader=loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_indirect_safe_loader_skipped():
    """Report nothing for ``yaml.load`` with a variable bound to ``yaml.SafeLoader``."""
    src = "import yaml\nloader = yaml.SafeLoader\nyaml.load(data, Loader=loader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_unknown_load_skipped():
    """Report nothing for an unqualified ``load`` call."""
    src = "load(data)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_safe_loader_assignment_after_call_does_not_mask_unsafe_call():
    """Report exactly one finding, with target ``yaml.load``, when a safe loader is assigned only after the call."""
    src = "import yaml\nyaml.load(data, Loader=loader)\nloader = yaml.SafeLoader\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert [f.metadata["target"] for f in findings] == ["yaml.load"]


def test_function_scoped_safe_loader_does_not_leak_to_other_function():
    """Report exactly one finding, with target ``yaml.load``, when the safe loader is bound only inside another function."""
    src = "import yaml\ndef safe_setup():\n    loader = yaml.SafeLoader\n    return loader\ndef attack(data):\n    yaml.load(data, Loader=loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert [f.metadata["target"] for f in findings] == ["yaml.load"]
