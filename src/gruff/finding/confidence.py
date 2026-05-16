"""How reliable a rule's heuristic signal is (low/medium/high)."""

from enum import StrEnum


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
