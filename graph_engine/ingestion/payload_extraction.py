"""Nested payload extraction — find base64-encoded URLs/emails in query strings.

Scans the query string and fragment of a URL for strings that look like
base64, decodes them, and reports any that resolve to a valid URL or email.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import urlparse, parse_qs

# Matches candidate base64 strings: len ≥ 20, valid alphabet + optional padding.
_B64_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _looks_like_base64(s: str) -> bool:
    """Quick heuristic: length, alphabet, and padding shape."""
    if len(s) < 20:
        return False
    # Must end with 0-2 padding chars if padding is present
    if s.endswith("="):
        stripped = s.rstrip("=")
        padding_len = len(s) - len(stripped)
        if padding_len > 2:
            return False
    return bool(_B64_RE.fullmatch(s))


def _try_decode_b64(s: str) -> str | None:
    """Try to decode *s* as base64 (with optional padding fix)."""
    # Try as-is
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass

    # Try with padding restored
    missing = len(s) % 4
    if missing:
        try:
            padded = s + "=" * (4 - missing)
            return base64.b64decode(padded, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    return None


def extract_nested_payloads(url: str) -> list[dict]:
    """Find base64-encoded URLs or email addresses in *url* query/fragment.

    Returns a list of dicts: ``{"raw": <base64_string>, "decoded": <decoded>,
    "kind": "url"|"email"}``.  Non-decodable or non-URL/email payloads are
    silently skipped.
    """
    results: list[dict] = []
    seen: set[str] = set()

    parsed = urlparse(url)
    # Collect all query values + fragment
    candidates: list[str] = []

    qs = parse_qs(parsed.query, keep_blank_values=True)
    for values in qs.values():
        for v in values:
            candidates.append(v)

    if parsed.fragment:
        candidates.append(parsed.fragment)

    # Also scan the full query string as one blob (some b64 payloads span
    # the entire query string, e.g. ?<b64 blob>).
    if parsed.query:
        candidates.append(parsed.query)

    for candidate in candidates:
        for match in _B64_RE.finditer(candidate):
            raw = match.group(0)
            if raw in seen:
                continue
            seen.add(raw)

            decoded = _try_decode_b64(raw)
            if decoded is None:
                continue

            decoded = decoded.strip()

            # Check if it's a valid URL
            try:
                p = urlparse(decoded)
                if p.scheme in ("http", "https") and p.netloc:
                    results.append({"raw": raw, "decoded": decoded, "kind": "url"})
                    continue
            except Exception:
                pass

            # Check if it's a valid email
            if _EMAIL_RE.match(decoded):
                results.append({"raw": raw, "decoded": decoded, "kind": "email"})

    return results
