"""Fingerprint algorithm for findings and baselines.

Byte-compatible with gruff-php's `Finding::fingerprint()` so baselines written by
gruff-php apply to gruff-py and vice versa. PHP's default `json_encode` flags escape
forward slashes as `\\/` and non-ASCII as `\\uXXXX`; this implementation reproduces
that exact byte output before hashing.
"""

import hashlib
import json
from typing import Any


def fingerprint_for(
    rule_id: str,
    file_path: str,
    line: int | None,
    end_line: int | None = None,
    column: int | None = None,
    symbol: str | None = None,
) -> str:
    """Compute the gruff-php-compatible 16-char fingerprint for a finding's identity.

    Payload key order is fixed (ruleId, file, line, endLine, column, symbol)
    so changing it would invalidate baselines across every implementation -
    do not reorder.

    Args:
        rule_id: Canonical rule id (e.g. ``"size.function-length"``).
        file_path: Display path of the offending file.
        line: 1-based starting line of the finding, or ``None``.
        end_line: 1-based last line covered by the finding.
        column: 1-based starting column.
        symbol: Qualified symbol name (function/class) when available.

    Returns:
        First 16 hex chars of SHA-256(canonical-JSON(payload)) - matches gruff-php.
    """
    payload = {
        "ruleId": rule_id,
        "file": file_path,
        "line": line,
        "endLine": end_line,
        "column": column,
        "symbol": symbol,
    }
    return _php_compatible_sha256_prefix(payload)


def stable_identity_for(
    rule_id: str,
    file_path: str,
    symbol: str | None,
    message: str,
) -> str:
    """Compute the line-insensitive 16-char identity for a finding.

    Pairs with ``fingerprint_for`` per ADR-020: ``fingerprint`` stays the
    line-precise identity used by baselines and SARIF; ``stableIdentity`` is
    line-insensitive for external diff tooling that wants "same logical
    finding" across unrelated line shifts.

    Input set: ``[ruleId, file, symbol]`` when ``symbol`` is not ``None``;
    ``[ruleId, file, message]`` when ``symbol`` is ``None``. No ``line``,
    ``end_line``, or ``column`` ever. Encoding matches ``fingerprint_for``
    byte-for-byte so cross-port consumers see identical digests for the same
    logical finding.

    Args:
        rule_id: Canonical rule id.
        file_path: Display path of the offending file.
        symbol: Qualified symbol when available; otherwise ``None``.
        message: Rendered finding message; consulted only when ``symbol`` is
            ``None`` (symbol-less fallback).

    Returns:
        First 16 hex chars of SHA-256(canonical-JSON(payload)).
    """
    if symbol is not None:
        payload: dict[str, Any] = {
            "ruleId": rule_id,
            "file": file_path,
            "symbol": symbol,
        }
    else:
        payload = {
            "ruleId": rule_id,
            "file": file_path,
            "message": message,
        }
    return _php_compatible_sha256_prefix(payload)


def _php_compatible_sha256_prefix(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    encoded = encoded.replace("/", r"\/")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
