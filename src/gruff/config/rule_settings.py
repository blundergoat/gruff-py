from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RuleSettings:
    enabled: bool = True
    thresholds: dict[str, int | float] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    def numeric_threshold(self, name: str) -> int | float:
        value = self.thresholds.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise LookupError(f'Missing numeric threshold "{name}".')
        return value

    def has_option(self, name: str) -> bool:
        return name in self.options

    def option(self, name: str) -> Any:
        if name not in self.options:
            raise LookupError(f'Missing option "{name}".')
        return self.options[name]

    def string_list_option(self, name: str) -> list[str]:
        value = self.options.get(name, [])
        if not isinstance(value, list):
            raise TypeError(f'Option "{name}" must be a list of strings.')
        for item in value:
            if not isinstance(item, str):
                raise TypeError(f'Option "{name}" must contain only strings.')
        return list(value)
