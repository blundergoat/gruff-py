"""Fingerprint algorithm for findings and baselines.

Byte-compatible with gruff-php's `Finding::fingerprint()` so baselines written by
gruff-php apply to gruff-py and vice versa. PHP's default `json_encode` flags escape
forward slashes as `\\/` and non-ASCII as `\\uXXXX`; this implementation reproduces
that exact byte output before hashing.
"""

import hashlib
import json


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
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    encoded = encoded.replace("/", r"\/")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
