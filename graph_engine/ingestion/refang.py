"""URL refanging — reverse common URL neutralisation patterns.

Idempotent: passing an already-clean URL is a no-op.
"""

from __future__ import annotations

import re

# Ordered by specificity — broader patterns last.
_PATTERNS = [
    # hxxps://  →  https://
    (re.compile(r"hxxps(?=://)", re.IGNORECASE), "https"),
    # hxxp://   →  http://   (must come after hxxps so it doesn't catch the 's')
    (re.compile(r"hxxp(?=://)", re.IGNORECASE), "http"),
    # hxxps     →  https    (without :// — e.g. "hxxps[://]" still needs the scheme fixed)
    (re.compile(r"\bhxxps\b", re.IGNORECASE), "https"),
    # hxxp      →  http
    (re.compile(r"\bhxxp\b", re.IGNORECASE), "http"),
    # [:]  →  :
    (re.compile(r"\[:\]", re.IGNORECASE), ":"),
    # [.] / (.) / {.}  →  .
    (re.compile(r"\[\.\]", re.IGNORECASE), "."),
    (re.compile(r"\(\s*\.\s*\)", re.IGNORECASE), "."),
    (re.compile(r"\{\s*\.\s*\}", re.IGNORECASE), "."),
    # [://]  →  ://
    (re.compile(r"\[://\]", re.IGNORECASE), "://"),
    # [at] / [@]  →  @
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[@\]", re.IGNORECASE), "@"),
    # wxw.  →  www.
    (re.compile(r"\bwxw\.", re.IGNORECASE), "www."),
    # Scheme with spaces: "h t t p : / /"  →  "http://"
    (re.compile(r"h\s+t\s+t\s+p\s*:\s*/\s*/\s*", re.IGNORECASE), "http://"),
    (re.compile(r"h\s+t\s+t\s+p\s+s\s*:\s*/\s*/\s*", re.IGNORECASE), "https://"),
    # " dot " → "."
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
    # " slash " → "/"
    (re.compile(r"\s+slash\s+", re.IGNORECASE), "/"),
]


def refang(raw: str) -> str:
    """Return *raw* with common defanging patterns reversed.

    Idempotent: ``refang(refang(url)) == refang(url)`` for any input.
    """
    result = raw.strip()
    for pat, replacement in _PATTERNS:
        result = pat.sub(replacement, result)
    return result
