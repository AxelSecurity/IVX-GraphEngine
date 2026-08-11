"""Pattern infrastrutturali noti per abuso.

Rileva: piattaforme serverless con abuso frequente, tunnel HTTP,
gateway IPFS, IP literal (v4/v6), e hostname con mescolanza di
script Unicode (omoglifi).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Categorie di infrastruttura abuse-prone
# ---------------------------------------------------------------------------

# Ogni entry: (nome_categoria, lista di pattern regex compilati)
_ABUSE_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "cloudflare-workers",
        re.compile(r"\.workers\.dev$", re.IGNORECASE),
    ),
    (
        "cloudflare-pages",
        re.compile(r"\.pages\.dev$", re.IGNORECASE),
    ),
    (
        "cloudflare-r2",
        re.compile(r"\.r2\.dev$", re.IGNORECASE),
    ),
    (
        "azure-blob",
        re.compile(r"\.blob\.core\.windows\.net$", re.IGNORECASE),
    ),
    (
        "firebase-hosting",
        re.compile(r"\.web\.app$", re.IGNORECASE),
    ),
    (
        "firebase-app",
        re.compile(r"\.firebaseapp\.com$", re.IGNORECASE),
    ),
    (
        "ipfs-gateway",
        re.compile(
            r"(?:ipfs\.io/ipfs/|\.ipfs\.dweb\.link$|cloudflare-ipfs\.com)",
            re.IGNORECASE,
        ),
    ),
    (
        "cloudflare-tunnel",
        re.compile(r"\.trycloudflare\.com$", re.IGNORECASE),
    ),
    (
        "ngrok-tunnel",
        re.compile(r"\.ngrok\.io$|\.ngrok-free\.app$", re.IGNORECASE),
    ),
    (
        "loca-lt-tunnel",
        re.compile(r"\.loca\.lt$", re.IGNORECASE),
    ),
]


def check_abuse_prone_infra(hostname: str) -> Optional[str]:
    """Restituisce il nome della categoria se *hostname* matcha un
    pattern di infrastruttura notoriamente abusata, altrimenti ``None``.
    """
    for category, pattern in _ABUSE_PATTERNS:
        if pattern.search(hostname):
            return category
    return None


# ---------------------------------------------------------------------------
# IP literal
# ---------------------------------------------------------------------------


def is_ip_literal(hostname: str) -> bool:
    """``True`` se *hostname* è un indirizzo IPv4 o IPv6 letterale."""
    # Rimuovi eventuali parentesi quadre IPv6
    stripped = hostname.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Mixed-script / omoglifi
# ---------------------------------------------------------------------------


# Blocchi Unicode per script comuni usati in attacchi omoglifi
_CYRILLIC = re.compile(r"[Ѐ-ӿ]")
_LATIN = re.compile(r"[a-zA-Z]")
_GREEK = re.compile(r"[Ͱ-Ͽ]")
_ARMENIAN = re.compile(r"[԰-֏]")

# Tutti i blocchi "script-like" rilevanti
_SCRIPT_BLOCKS = [
    ("cyrillic", _CYRILLIC),
    ("latin", _LATIN),
    ("greek", _GREEK),
    ("armenian", _ARMENIAN),
]


def has_mixed_script(hostname: str) -> bool:
    """``True`` se *hostname* contiene caratteri di più di uno script
    Unicode (es. Cirillico + Latino), pattern tipico degli attacchi
    omoglifi / IDN homograph.
    """
    # Decodifica IDN punycode se necessario (es. xn--...)
    # L'hostname in input potrebbe già essere decodificato (da canonicalize)
    # o essere ancora in forma punycode.
    try:
        decoded = hostname.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        decoded = hostname

    active_scripts = 0
    for _name, pattern in _SCRIPT_BLOCKS:
        if pattern.search(decoded):
            active_scripts += 1
            if active_scripts >= 2:
                return True
    return False
