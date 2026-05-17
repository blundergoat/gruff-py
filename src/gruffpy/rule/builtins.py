"""Compatibility exports for the built-in rule catalog."""

from gruffpy.rule.catalog import BUILTIN_RULES, BuiltInRule, RuleDocs, RuleFactory, default_rules

__all__ = [
    "BUILTIN_RULES",
    "BuiltInRule",
    "RuleDocs",
    "RuleFactory",
    "default_rules",
]
