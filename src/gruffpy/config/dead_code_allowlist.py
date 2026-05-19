"""Allowlist applied to dead-code findings before reporting.

Filters findings emitted by ``dead-code.unused-private-function`` and
``dead-code.unused-private-attribute``. See ADR-015 for the design contract.
"""

import fnmatch
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeadCodeAllowlist:
    """Path/symbol/decorator allowlist consumed by dead-code rules.

    Attributes:
        symbols: Exact qualified symbols allowed to appear unused.
        decorators: Decorators that mark otherwise-unused symbols as allowed.
        paths: Display-path globs whose dead-code findings are allowed.
    """

    symbols: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def matches_symbol(self, symbol: str | None) -> bool:
        """Return whether *symbol* is on the allowlist's exact-match symbol list.

        Args:
            symbol: Qualified symbol (``Module.Class.method``) or ``None``.

        Returns:
            True for an exact symbol match; ``None`` always returns False.
        """
        return symbol is not None and symbol in self.symbols

    def matches_path(self, file_path: str) -> bool:
        """Return whether *file_path* matches any configured glob.

        Uses case-sensitive :func:`fnmatch.fnmatchcase` so wildcards
        (``*``, ``?``, ``[...]``) work but the match is not regex.

        Args:
            file_path: Display path of a parsed source file.

        Returns:
            True when any configured glob matches.
        """
        return any(fnmatch.fnmatchcase(file_path, pattern) for pattern in self.paths)

    def matches_decorator(self, decorator_names: tuple[str, ...]) -> bool:
        """Return whether any of *decorator_names* is on the decorator allowlist.

        Callers typically pass both the fully-qualified decorator name
        (``module.Class.decorator``) and its leaf so the allowlist can be
        spelled either way.

        Args:
            decorator_names: Names of decorators on the candidate symbol.

        Returns:
            True if at least one decorator is in the configured allowlist.
        """
        if not self.decorators:
            return False
        allowed = set(self.decorators)
        return any(name in allowed for name in decorator_names)
