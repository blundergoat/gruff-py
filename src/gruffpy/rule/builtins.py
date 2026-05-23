"""Compatibility re-exports for callers that import the built-in rule catalog module."""

from gruffpy.rule.catalog import BUILTIN_RULES, BuiltInRule, RuleDocs, RuleFactory, default_rules

__all__ = [
    "BUILTIN_RULES",
    "BuiltInRule",
    "RuleDocs",
    "RuleFactory",
    "default_rules",
]
