"""URL unwrapping — resolve wrapper/redirector services to their target URL.

Supports: Microsoft SafeLinks, Proofpoint URLDefense (v2/v3), Mimecast,
Barracuda LinkProtect, and generic open-redirect parameters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse, urlunparse


@dataclass
class UnwrapStep:
    """One hop in the unwrap chain."""

    wrapper_type: str
    input_url: str
    output_url: str
    opaque: bool = False  # True when target is not decodable client-side


@dataclass
class UnwrapResult:
    """Full unwrap chain for a single input URL."""

    final_url: str
    chain: list[UnwrapStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SafeLinks
# ---------------------------------------------------------------------------

_SAFELINKS_DOMAINS = (
    "safelinks.protection.outlook.com",
    "safelinks.protection.office365.us",
    "safelinks.protection.office365.com",
)


def _try_safelinks(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    if not any(
        parsed.hostname == d or parsed.hostname.endswith("." + d)
        for d in _SAFELINKS_DOMAINS
    ):
        return None
    qs = parse_qs(parsed.query)
    target = qs.get("url", [None])[0]
    return target


# ---------------------------------------------------------------------------
# Proofpoint URLDefense v2
# ---------------------------------------------------------------------------

_PROOFPOINT_V2_HOSTS = (
    "urldefense.proofpoint.com",
    "urldefense.com",
)

# v2 query param contains an encoding with substitutions.
# Pattern: u=<encoded> where _ → /, - → +, then percent-decode.
# Sometimes followed by &k=...&d=...&c=... — we only need &u=.
_PROOFPOINT_V2_RE = re.compile(r"(?:^|[?&])u=([^&?#]+)")


def _decode_proofpoint_v2(encoded: str) -> str:
    """Apply Proofpoint v2 substitutions then percent-decode.

    Real v2 encoding: / → _, then percent-encode, then % → -.
    Decoding reverses: - → %, _ → /, then percent-decode.
    """
    substituted = encoded.replace("-", "%").replace("_", "/")
    from urllib.parse import unquote
    return unquote(substituted)


def _try_proofpoint_v2(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    if not any(
        parsed.hostname == d or parsed.hostname.endswith("." + d)
        for d in _PROOFPOINT_V2_HOSTS
    ):
        return None
    if "/v2/" not in parsed.path:
        return None
    m = _PROOFPOINT_V2_RE.search(parsed.query)
    if not m:
        return None
    return _decode_proofpoint_v2(m.group(1))


# ---------------------------------------------------------------------------
# Proofpoint URLDefense v3
# ---------------------------------------------------------------------------

# v3 format: /v3/__<encoded_target>__;<checksum>__<rest>__
# The target is between the first pair of double-underscores.
_PROOFPOINT_V3_RE = re.compile(r"/v3/__([^_;]+)__")


def _try_proofpoint_v3(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.hostname:
        return None
    if not any(
        parsed.hostname == d or parsed.hostname.endswith("." + d)
        for d in _PROOFPOINT_V2_HOSTS
    ):
        return None
    m = _PROOFPOINT_V3_RE.search(parsed.path)
    if not m:
        return None
    from urllib.parse import unquote
    return unquote(m.group(1))


# ---------------------------------------------------------------------------
# Mimecast
# ---------------------------------------------------------------------------

_MIMECAST_HOST_RE = re.compile(r"(?:\.|^)mimecast\.com$|(?:\.|^)protect\.mimecast\.com$")


def _try_mimecast(url: str) -> str | None:
    """Mimecast targets are often encrypted server-side — mark as opaque."""
    parsed = urlparse(url)
    if not _MIMECAST_HOST_RE.search(parsed.hostname or ""):
        return None
    # Check for a url= query param
    qs = parse_qs(parsed.query)
    target = qs.get("url", [None])[0]
    if target:
        return target
    return None  # opaque — no decodable target found


# ---------------------------------------------------------------------------
# Barracuda LinkProtect
# ---------------------------------------------------------------------------

_BARRACUDA_HOSTS = ("linkprotect.cudasvc.com",)


def _try_barracuda(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.hostname not in _BARRACUDA_HOSTS:
        return None
    qs = parse_qs(parsed.query)
    target = qs.get("a", [None])[0]
    return target


# ---------------------------------------------------------------------------
# Generic open-redirect parameters
# ---------------------------------------------------------------------------

_OPEN_REDIRECT_PARAMS = ("url", "next", "redirect", "dest", "u", "target",
                         "return", "return_url", "returnurl", "goto",
                         "redir", "link", "uri", "forward")


def _try_open_redirect(url: str) -> str | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in _OPEN_REDIRECT_PARAMS:
        val = qs.get(param, [None])[0]
        if val:
            try:
                candidate = urlparse(val)
                if candidate.scheme in ("http", "https") and candidate.netloc:
                    return val
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

_WRAPPERS = [
    ("safe-links", _try_safelinks),
    ("proofpoint-v2", _try_proofpoint_v2),
    ("proofpoint-v3", _try_proofpoint_v3),
    ("mimecast", _try_mimecast),
    ("barracuda", _try_barracuda),
    ("open-redirect", _try_open_redirect),
]


def unwrap_url(url: str, max_hops: int = 5) -> UnwrapResult:
    """Iteratively unwrap *url* through recognised wrapper services.

    Returns an ``UnwrapResult`` whose ``final_url`` is the innermost
    decodable target and ``chain`` lists every unwrap step encountered.

    If no wrapper is recognised, ``final_url == url`` and ``chain`` is
    empty.
    """
    current = url
    chain: list[UnwrapStep] = []

    for _ in range(max_hops):
        matched = False
        for name, detector in _WRAPPERS:
            target = detector(current)
            if target is not None:
                opaque = name == "mimecast"
                chain.append(UnwrapStep(
                    wrapper_type=name,
                    input_url=current,
                    output_url=target,
                    opaque=opaque,
                ))
                current = target
                matched = True
                break

        if not matched:
            break

    return UnwrapResult(final_url=current, chain=chain)
