"""URL canonicalization — normalise + hash for deduplication.

Produces a ``(canonical_url, url_hash)`` tuple suitable for
``AnalysisTarget.canonical_url`` and ``AnalysisTarget.url_hash``.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

_IDN_PREFIX = "xn--"


def _decode_idn(hostname: str) -> str:
    """Decode punycode/IDN to Unicode if present."""
    if _IDN_PREFIX not in hostname:
        return hostname
    try:
        # The stdlib 'encodings.idna' handles both single-label and
        # multi-label punycode (see RFC 3490 / 5891).
        return hostname.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return hostname


def _decode_percent_iterative(s: str, max_iter: int = 5) -> str:
    """Decode percent-encoding repeatedly until stable (within *max_iter*)."""
    prev = s
    for _ in range(max_iter):
        decoded = unquote(prev)
        if decoded == prev:
            return decoded
        prev = decoded
    return prev


def _sort_query(query: str) -> str:
    """Sort query parameters alphabetically for hash stability."""
    if not query:
        return query
    params = parse_qsl(query, keep_blank_values=True)
    params.sort(key=lambda kv: kv[0])
    return urlencode(params, quote_via=quote)


def canonicalize_and_hash(url: str) -> tuple[str, str]:
    """Normalise *url* and compute its SHA-256 hash.

    Steps:
    1. Decode punycode hostname to Unicode.
    2. Decode percent-encoding iteratively (nested encoding).
    3. Lower-case scheme + hostname.
    4. Remove default port (:80 / :443).
    5. Sort query string alphabetically.
    6. Compute SHA-256 of the canonical form.

    Returns ``(canonical_url, url_hash)``.
    """
    parsed = urlparse(url)

    # Scheme + hostname to lower case
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    # Decode IDN
    hostname = _decode_idn(hostname)

    # Remove default port
    port: str | None = None
    if parsed.port is not None:
        if (scheme == "http" and parsed.port == 80) or \
           (scheme == "https" and parsed.port == 443):
            port = None  # omit default port
        else:
            port = str(parsed.port)

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    # Decode percent-encoding in path, query, fragment
    path = _decode_percent_iterative(parsed.path) if parsed.path else ""
    query = _sort_query(_decode_percent_iterative(parsed.query)) if parsed.query else ""
    fragment = _decode_percent_iterative(parsed.fragment) if parsed.fragment else ""

    canonical = urlunparse((scheme, netloc, path, "", query, fragment))

    url_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return canonical, url_hash
