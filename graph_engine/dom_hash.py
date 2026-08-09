"""DOM normalisation and content-based hashing.

Implements the strategy described in ARCHITECTURE_L4.md:
- Strip nonces, CSRF tokens, timestamps, UUIDs from attributes / text.
- Sort attributes alphabetically.
- Return SHA-256 of the canonical serialised tree.
"""

from __future__ import annotations

import hashlib
import re

from lxml import etree, html


# ---------------------------------------------------------------------------
# Patterns that identify ephemeral / non-deterministic values
# ---------------------------------------------------------------------------

# Attribute *names* that should always be dropped.
_STRIP_ATTR_NAMES: set[str] = {"nonce"}

# Attribute names containing any of these substrings are dropped.
_STRIP_ATTR_SUBSTRINGS: tuple[str, ...] = ("csrf", "token")

# Attribute *values* matching these regexes are dropped (ephemeral).
_EPHEMERAL_VALUE_PATTERNS: list[re.Pattern] = [
    re.compile(r"^\d{10,13}$"),  # Unix timestamp (seconds or ms)
    re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),  # ISO-8601 datetime
    re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ),  # UUID
    re.compile(r"^[0-9a-fA-F]{32}$"),  # MD5
    re.compile(r"^[0-9a-fA-F]{40}$"),  # SHA1
    re.compile(r"^[0-9a-fA-F]{64}$"),  # SHA256
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _value_contains_ephemeral_substring(value: str) -> bool:
    """Return True if the attribute *value* contains a CSRF/token keyword."""
    lower = value.lower()
    return any(sub in lower for sub in _STRIP_ATTR_SUBSTRINGS)


def _attr_name_should_strip(name: str) -> bool:
    """Return True if the attribute *name* should be stripped entirely."""
    if name in _STRIP_ATTR_NAMES:
        return True
    lower = name.lower()
    return any(sub in lower for sub in _STRIP_ATTR_SUBSTRINGS)


def _attr_value_is_ephemeral(value: str) -> bool:
    """Return True if the attribute *value* looks like a timestamp / UUID / hash,
    or contains a known ephemeral substring (csrf, token, …)."""
    if _value_contains_ephemeral_substring(value):
        return True
    return any(pat.search(value) for pat in _EPHEMERAL_VALUE_PATTERNS)


def _normalise_element(el: etree._Element) -> None:
    """Recursively normalise an lxml Element in-place."""
    # --- attributes ---------------------------------------------------------
    # Pre-scan: does any attribute *value* signal that this element carries
    # ephemeral data (csrf token, timestamp, UUID, …)?  If so, also drop the
    # ``value`` attribute — it is the token payload and would otherwise
    # differ on every request.
    has_ephemeral_signal = any(
        _attr_value_is_ephemeral(v) for v in el.attrib.values()
    )

    kept: list[tuple[str, str]] = []
    for name, value in el.attrib.items():
        if _attr_name_should_strip(name):
            continue
        if _attr_value_is_ephemeral(value):
            if name.lower() in ("id", "class"):
                kept.append((name, value))
            continue
        # CASCADE: when the element carried an ephemeral signal, drop the
        # ``value`` attribute too (it is the token payload).
        if has_ephemeral_signal and name.lower() == "value":
            continue
        kept.append((name, value))

    # Sort by name, then by value for determinism.
    kept.sort(key=lambda kv: (kv[0], kv[1]))

    # Rebuild attributes in sorted order.
    el.attrib.clear()
    for name, value in kept:
        el.set(name, value)

    # --- children -----------------------------------------------------------
    for child in el:
        _normalise_element(child)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalise_and_hash(html_str: str) -> str:
    """Normalise an HTML string and return its SHA-256 hex digest.

    The normalisation removes ephemeral attributes (nonce, CSRF token,
    timestamps, UUIDs) and sorts attributes alphabetically so that two
    logically-equivalent pages produce the **same** hash.
    """
    # Parse into a tree.  html.fragment_fromstring handles partial HTML
    # (no <html>/<body> wrapper required) gracefully.
    try:
        tree = html.fragment_fromstring(html_str, create_parent="div")
    except Exception:
        # If parsing fails entirely (e.g. bare text), hash the raw input.
        return hashlib.sha256(html_str.encode("utf-8")).hexdigest()

    _normalise_element(tree)

    # Serialise back to a canonical byte-string.
    # method="html" emits self-closing tags where appropriate.
    canonical = html.tostring(tree, encoding="unicode", method="html")

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
