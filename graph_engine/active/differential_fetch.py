"""Differential fetch — confronto tra profili HTTP per rilevare cloaking.

Esegue la stessa richiesta con diversi User-Agent / header e confronta
le risposte. Se i profili ricevono contenuti diversi (status code, URL
finale o hash del body), viene rilevato cloaking e raccomandato il
profilo "più ricco" da usare in L4.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Callable

import httpx


# ---------------------------------------------------------------------------
# Profili predefiniti (minimo 4, come da specifica)
# ---------------------------------------------------------------------------

PROFILES: dict[str, dict] = {
    "desktop_chrome": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "headers": {
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,*/*;q=0.8"
            ),
            "Sec-Ch-Ua": (
                '"Google Chrome";v="125", "Chromium";v="125", '
                '"Not.A/Brand";v="24"'
            ),
            "Sec-Ch-Ua-Platform": '"Windows"',
        },
        "referer": True,  # invia Referer naturale
    },
    "mobile_safari": {
        "user_agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.5 Mobile/15E148 Safari/604.1"
        ),
        "headers": {
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        "referer": True,
    },
    "bot_googlebot": {
        "user_agent": (
            "Mozilla/5.0 (compatible; Googlebot/2.1; "
            "+http://www.google.com/bot.html)"
        ),
        "headers": {
            "Accept-Language": "*",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "From": "googlebot@google.com",
        },
        "referer": False,
    },
    "no_referer_desktop": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "headers": {
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,*/*;q=0.8"
            ),
        },
        "referer": False,  # nessun Referer
    },
}


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------


def _make_client_for_profile(profile: dict, timeout: float = 15.0) -> httpx.AsyncClient:
    """Crea un ``httpx.AsyncClient`` configurato con gli header del profilo."""
    headers = dict(profile.get("headers", {}))
    headers["User-Agent"] = profile["user_agent"]

    # Referer non viene impostato come header fisso — è generato da httpx
    # durante i redirect. Se il profilo dice referer=False, non lo blocchiamo
    # esplicitamente (httpx non lo invia se non c'è un referer naturale).

    return httpx.AsyncClient(
        headers=headers,
        follow_redirects=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def differential_fetch(
    url: str,
    client_factory: Callable[[dict], httpx.AsyncClient] | None = None,
    profiles: dict[str, dict] | None = None,
) -> dict:
    """Esegue una richiesta per ciascun profilo IN PARALLELO.

    Args:
        url: URL da interrogare.
        client_factory: Factory che crea un ``httpx.AsyncClient`` da un
            profilo (default: ``_make_client_for_profile``).
        profiles: Profili da usare (default: ``PROFILES``).

    Returns:
        dict con chiavi:
        - ``results``: dict[profile_name, dict] — per ogni profilo:
          ``status_code``, ``final_url``, ``content_length``,
          ``body_sha256``, ``error`` (solo se fallito)
        - ``profiles_compared``: int — numero di profili confrontati con
          successo (senza errori)
    """
    if profiles is None:
        profiles = PROFILES
    if client_factory is None:
        client_factory = _make_client_for_profile

    async def _fetch_one(name: str, profile: dict) -> tuple[str, dict]:
        result: dict = {
            "status_code": None,
            "final_url": None,
            "content_length": None,
            "body_sha256": None,
        }
        try:
            async with client_factory(profile) as client:
                response = await client.get(url)
                result["status_code"] = response.status_code
                result["final_url"] = str(response.url)
                body = response.content
                result["content_length"] = len(body) if body else 0
                if body:
                    result["body_sha256"] = hashlib.sha256(body).hexdigest()
        except Exception as exc:
            result["error"] = str(exc)
        return name, result

    tasks = [_fetch_one(name, profile) for name, profile in profiles.items()]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, dict] = {}
    for item in gathered:
        if isinstance(item, Exception):
            # Non dovrebbe succedere con return_exceptions=True, ma per sicurezza
            continue
        name, result = item
        results[name] = result

    return {
        "results": results,
        "profiles_compared": sum(
            1 for r in results.values() if "error" not in r
        ),
    }


# ---------------------------------------------------------------------------
# Cloaking detection
# ---------------------------------------------------------------------------


def detect_cloaking(results: dict[str, dict]) -> dict:
    """Confronta le risposte tra profili e rileva cloaking.

    Il cloaking viene rilevato se:
    - Status code divergono tra profili (es. 200 vs 403)
    - URL finali divergono (redirect diversi)
    - Content hash divergono (body diverso)

    Args:
        results: dict ``{profile_name: {...}}``, il sotto-dict ``results``
            restituito da ``differential_fetch()``.

    Returns:
        dict con:
        - ``cloaking_detected``: bool
        - ``divergent_profiles``: list[str] — nomi dei profili con
          risposta divergente (vuoto se nessun cloaking)
        - ``divergence_details``: str — spiegazione
    """
    successful = {
        name: r for name, r in results.items() if "error" not in r
    }

    if len(successful) < 2:
        return {
            "cloaking_detected": False,
            "divergent_profiles": [],
            "divergence_details": "Meno di 2 profili hanno avuto successo",
        }

    # Raccogli i valori unici per ogni dimensione
    status_codes = {r["status_code"] for r in successful.values()}
    final_urls = {r["final_url"] for r in successful.values()}
    body_hashes = {r["body_sha256"] for r in successful.values()}

    divergent_profiles: list[str] = []

    if len(status_codes) > 1:
        # Trova i profili che divergono dalla maggioranza
        divergent_profiles = _find_divergent(
            successful, lambda r: r["status_code"]
        )

    if not divergent_profiles and len(final_urls) > 1:
        divergent_profiles = _find_divergent(
            successful, lambda r: r["final_url"]
        )

    if not divergent_profiles and len(body_hashes) > 1:
        divergent_profiles = _find_divergent(
            successful, lambda r: r["body_sha256"]
        )

    if divergent_profiles:
        return {
            "cloaking_detected": True,
            "divergent_profiles": divergent_profiles,
            "divergence_details": (
                f"Profili divergenti: {', '.join(divergent_profiles)}. "
                f"Status codes: {status_codes}, "
                f"URL finali: {len(final_urls)} distinti, "
                f"Body hash: {len(body_hashes)} distinti"
            ),
        }

    return {
        "cloaking_detected": False,
        "divergent_profiles": [],
        "divergence_details": "Tutti i profili hanno ricevuto la stessa risposta",
    }


def _find_divergent(
    successful: dict[str, dict],
    key_fn: Callable,
) -> list[str]:
    """Trova i profili il cui valore (via key_fn) diverge dalla maggioranza."""
    from collections import Counter

    values = [key_fn(r) for r in successful.values()]
    counts = Counter(values)
    majority_value = counts.most_common(1)[0][0]

    return [
        name for name, r in successful.items()
        if key_fn(r) != majority_value
    ]


# ---------------------------------------------------------------------------
# Raccomandazione profilo
# ---------------------------------------------------------------------------


def recommend_profile(
    results: dict[str, dict],
    cloaking: dict,
) -> dict:
    """Raccomanda il profilo da usare in L4 (Playwright).

    Se cloaking rilevato, raccomanda il profilo che ha ricevuto la
    risposta "più ricca" (content_length maggiore, o quello su cui
    converge la maggioranza). Se nessun cloaking, raccomanda
    desktop_chrome di default.

    Args:
        results: dict ``{profile_name: {...}}`` da ``differential_fetch()``.
        cloaking: dict da ``detect_cloaking()``.

    Returns:
        dict con ``user_agent`` e ``headers`` pronti per
        ``browser.new_context()`` di Playwright.
    """
    if not cloaking.get("cloaking_detected"):
        # Default: desktop Chrome
        profile = PROFILES.get("desktop_chrome", PROFILES["desktop_chrome"])
        return {
            "user_agent": profile["user_agent"],
            "headers": dict(profile.get("headers", {})),
        }

    # Cloaking rilevato — scegli il profilo "più ricco"
    successful = {
        name: r for name, r in results.items()
        if "error" not in r and name not in cloaking.get("divergent_profiles", [])
    }

    # Se tutti i profili non-divergenti sono falliti, prendi il migliore tra
    # quelli divergenti per content_length
    if not successful:
        successful = {
            name: PROFILES.get(name, PROFILES["desktop_chrome"])
            for name in cloaking.get("divergent_profiles", [])
        }
        # Fallback: prendi il primo profilo divergente
        if cloaking.get("divergent_profiles"):
            name = cloaking["divergent_profiles"][0]
            profile = PROFILES.get(name, PROFILES["desktop_chrome"])
            return {
                "user_agent": profile["user_agent"],
                "headers": dict(profile.get("headers", {})),
            }
        # Ultimo fallback
        return {
            "user_agent": PROFILES["desktop_chrome"]["user_agent"],
            "headers": dict(PROFILES["desktop_chrome"].get("headers", {})),
        }

    # Scegli il profilo con content_length maggiore
    best_name = max(
        successful.keys(),
        key=lambda n: results.get(n, {}).get("content_length", 0),
    )
    profile = PROFILES.get(best_name, PROFILES["desktop_chrome"])
    return {
        "user_agent": profile["user_agent"],
        "headers": dict(profile.get("headers", {})),
    }
