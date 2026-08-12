"""Risoluzione DNS A/AAAA — record IPv4 e IPv6.

Usa ``loop.getaddrinfo`` (nativamente asincrono) per risolvere
entrambe le famiglie di indirizzi. Nessuna dipendenza esterna —
``getaddrinfo`` è già nel loop di ``asyncio``.

La cache filesystem (``graph_engine.osint.cache``) evita di
ri-risolvere lo stesso hostname entro il TTL (1 ora).
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

from graph_engine.osint.cache import TTL_DNS, cache_get, cache_set

# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

_DNS_TIMEOUT = 5.0  # secondi — un DNS che non risponde non deve appendere

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def resolve_dns(hostname: str) -> dict:
    """Risolve i record A (IPv4) e AAAA (IPv6) per *hostname*.

    Args:
        hostname: Nome host da risolvere (es. ``"example.com"``).

    Returns:
        dict con chiavi:
        - ``a_records``: list[str] — indirizzi IPv4
        - ``aaaa_records``: list[str] — indirizzi IPv6
        - ``error``: str | None — messaggio di errore se la risoluzione
          fallisce, ``None`` altrimenti

        Non rilancia MAI eccezioni — gli errori diventano ``error`` popolato
        e liste vuote.
    """
    # ── Cache ──────────────────────────────────────────────────────────
    cached = cache_get("dns", hostname, TTL_DNS)
    if cached is not None:
        return cached

    # ── Risoluzione ────────────────────────────────────────────────────
    loop = asyncio.get_running_loop()

    async def _resolve(family: int) -> list[str]:
        """Risolve *hostname* per la famiglia di indirizzi *family*."""
        try:
            addrinfo = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=family, type=0, proto=0),
                timeout=_DNS_TIMEOUT,
            )
            # getaddrinfo restituisce una lista di tuple a 5 elementi;
            # l'indirizzo IP è in sockaddr[0] (il primo elemento della
            # tupla finale)
            addresses: list[str] = []
            for _, _, _, _, sockaddr in addrinfo:
                addr = sockaddr[0]
                if addr not in addresses:
                    addresses.append(addr)
            return addresses
        except (asyncio.TimeoutError, OSError):
            return []

    try:
        a_records, aaaa_records = await asyncio.gather(
            _resolve(socket.AF_INET),
            _resolve(socket.AF_INET6),
        )
    except Exception as exc:
        result = {
            "a_records": [],
            "aaaa_records": [],
            "error": f"DNS resolution failed: {exc}",
        }
        cache_set("dns", hostname, result)
        return result

    # ── Interpretazione risultato ──────────────────────────────────────
    if not a_records and not aaaa_records:
        result = {
            "a_records": [],
            "aaaa_records": [],
            "error": f"No DNS records found for {hostname}",
        }
    else:
        result = {
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "error": None,
        }

    cache_set("dns", hostname, result)
    return result
