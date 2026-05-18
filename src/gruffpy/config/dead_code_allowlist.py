"""Allowlist applied to dead-code findings before reporting.

Filters findings emitted by ``dead-code.unused-private-function`` and
``dead-code.unused-private-attribute``. See ADR-015 for the design contract.
"""

import fnmatch
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeadCodeAllowlist:
    symbols: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def matches_symbol(self, symbol: str | None) -> bool:
        return symbol is not None and symbol in self.symbols

    def matches_path(self, file_path: str) -> bool:
        return any(fnmatch.fnmatchcase(file_path, pattern) for pattern in self.paths)

    def matches_decorator(self, decorator_names: tuple[str, ...]) -> bool:
        if not self.decorators:
            return False
        allowed = set(self.decorators)
        return any(name in allowed for name in decorator_names)
