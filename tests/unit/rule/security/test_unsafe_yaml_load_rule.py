from gruffpy.rule.security.unsafe_yaml_load_rule import UnsafeYamlLoadRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_yaml_unsafe_load_emits():
    src = "import yaml\nyaml.unsafe_load(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["target"] == "yaml.unsafe_load"
    assert findings[0].metadata["sourceLabel"] == "yaml-input"
    assert findings[0].metadata["sinkLabel"] == "unsafe-yaml-loader"


def test_yaml_load_without_loader_emits():
    src = "import yaml\nyaml.load(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_loader_emits():
    src = "import yaml\nyaml.load(data, Loader=yaml.Loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_unsafe_loader_emits():
    src = "import yaml\nyaml.load(data, Loader=yaml.UnsafeLoader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_imported_alias_emits():
    src = "from yaml import unsafe_load as load_yaml\nload_yaml(data)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_safe_load_skipped():
    src = "import yaml\nyaml.safe_load(data)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_safe_loader_skipped():
    src = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_positional_safe_loader_skipped():
    src = "import yaml\nyaml.load(data, yaml.SafeLoader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_yaml_load_with_positional_unsafe_loader_emits():
    src = "import yaml\nyaml.load(data, yaml.Loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_indirect_unsafe_loader_emits():
    src = "import yaml\nloader = yaml.Loader\nyaml.load(data, Loader=loader)\n"
    findings = UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_yaml_load_with_indirect_safe_loader_skipped():
    src = "import yaml\nloader = yaml.SafeLoader\nyaml.load(data, Loader=loader)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []


def test_unknown_load_skipped():
    src = "load(data)\n"
    assert UnsafeYamlLoadRule().analyse(make_unit(src), default_ctx()) == []
