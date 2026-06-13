"""Top-level quality dimensions a rule contributes to (size, complexity, ...)."""

from enum import StrEnum


class Pillar(StrEnum):
    SIZE = "size"
    COMPLEXITY = "complexity"
    CORRECTNESS = "correctness"
    COUPLING = "coupling"
    DEAD_CODE = "dead-code"
    NAMING = "naming"
    DOCUMENTATION = "documentation"
    SECURITY = "security"
    SENSITIVE_DATA = "sensitive-data"
    DESIGN = "design"
    MODERNISATION = "modernisation"
    TEST_QUALITY = "test-quality"
    ARCHITECTURE = "architecture"
    MAINTAINABILITY = "maintainability"
    MUTATION = "mutation"
