"""Release-tier marker rules use to gate themselves against gruff versions."""

from enum import StrEnum


class RuleTier(StrEnum):
    V01 = "v0.1"
