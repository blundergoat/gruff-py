import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.generic_function_rule import GenericFunctionRule
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx(options: dict | None = None) -> RuleContext:
    rule = GenericFunctionRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True, options=options or {})}),
    )


def test_process_fires():
    src = "def process(x): return x\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "process"


def test_handle_fires():
    src = "def handle(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_do_fires():
    src = "def do(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_process_payment_does_not_fire():
    src = "def process_payment(x): return x\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_handle_request_does_not_fire():
    src = "def handle_request(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_method_generic_fires():
    src = "class C:\n    def execute(self): pass\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "C.execute"


def test_non_generic_does_not_fire():
    src = "def calculate(): return 1\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_configurable_replacement():
    src = "def calculate(): return 1\n"
    findings = GenericFunctionRule().analyse(_unit(src), _ctx(options={"genericFunctions": ["calculate"]}))
    assert len(findings) == 1


@pytest.mark.parametrize(
    "source",
    [
        "from django.core.management.base import BaseCommand\nclass Command(BaseCommand):\n    def handle(self): pass\n",
        "from django.core.management.base import BaseCommand as CommandBase\nclass Command(CommandBase):\n    def execute(self): pass\n",
        "from docutils.parsers.rst import Directive\nclass HazmatDirective(Directive):\n    def run(self): pass\n",
        "import threading\nclass Transport(threading.Thread):\n    def run(self): pass\n",
        "import logging\ndef test_loader():\n    class _TestHandler(logging.Handler):\n        def handle(self): pass\n",
        "import django.core.management.base as commands\nclass Command(commands.BaseCommand):\n    def handle(self): pass\n",
    ],
    ids=["django-handle", "django-execute-alias", "docutils-run", "threading-run", "nested-logging-handle", "django-module-alias"],
)
def test_required_framework_method_stays_quiet(source):
    """Preserve required dispatch names on unambiguous imported framework bases.

    Args:
        source: A required override from an observed framework family.
    """
    assert GenericFunctionRule().analyse(_unit(source), _ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        "import threading\nclass Worker(threading.Thread):\n    def process(self): pass\n",
        "class Command(BaseCommand):\n    def handle(self): pass\n",
        "class BaseCommand: pass\nclass Command(BaseCommand):\n    def handle(self): pass\n",
    ],
    ids=["unrelated-method", "unimported-base", "local-base"],
)
def test_unproven_framework_method_still_fires(source):
    """Keep findings when the base or required method identity is unproven.

    Args:
        source: A generic method without a recognized required-hook contract.
    """
    findings = GenericFunctionRule().analyse(_unit(source), _ctx())
    assert len(findings) == 1


@pytest.mark.parametrize(
    "shadow",
    [
        "Thread = object\n",
        "def configure(Thread): pass\n",
        "from local_workers import Thread\n",
    ],
    ids=["assigned-import", "parameter-shadow", "reimported-base"],
)
def test_shadowed_framework_import_still_fires(shadow):
    """Retain naming findings when imported-base resolution is ambiguous.

    Args:
        shadow: A binding that prevents proving the imported framework identity.
    """
    source = f"from threading import Thread\n{shadow}class Worker(Thread):\n    def run(self): pass\n"
    findings = GenericFunctionRule().analyse(_unit(source), _ctx())
    assert len(findings) == 1


def test_nested_function_inside_framework_method_still_fires():
    """Exempt the direct override while preserving a generic nested function."""
    source = "import threading\nclass Worker(threading.Thread):\n    def run(self):\n        def run(): pass\n"
    findings = GenericFunctionRule().analyse(_unit(source), _ctx())
    assert [finding.symbol for finding in findings] == ["Worker.run.run"]


def test_async_function_still_fires():
    """Keep generic async functions reportable outside a required override."""
    findings = GenericFunctionRule().analyse(_unit("async def run(): pass\n"), _ctx())
    assert len(findings) == 1


def test_default_off_and_explicit_enable_use_the_same_detector():
    """Keep a below-floor rule opt-in while preserving explicit enabled output."""
    registry = RuleRegistry.defaults()
    unit = _unit("def process(): pass\n")
    config = AnalysisConfig.from_registry(registry)
    context = RuleContext(project_root="/", config=config)
    assert not GenericFunctionRule().definition().default_enabled
    assert not any(finding.rule_id == GenericFunctionRule.ID for finding in registry.analyse([unit], context))
    config.rules[GenericFunctionRule.ID] = RuleSettings(enabled=True)
    enabled = [finding for finding in registry.analyse([unit], context) if finding.rule_id == GenericFunctionRule.ID]
    assert len(enabled) == 1
    assert enabled[0].remediation == "Rename 'process' to ``process_<noun>``."
