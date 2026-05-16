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
