"""Certificate Transparency via crt.sh — domini fratelli di campagna.

Interroga l'API pubblica crt.sh per estrarre la lista SAN (Subject
Alternative Name) aggregata di tutti i certificati noti per un dominio.

Il segnale a più alto valore è la **SAN list deduplicata**: i domini
che condividono un certificato con il dominio target sono potenziali
domini fratelli della stessa campagna di phishing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from graph_engine.osint.cache import TTL_CRTSH, cache_get, cache_set

# ---------------------------------------------------------------------------
# Limiti
# ---------------------------------------------------------------------------

MAX_SIBLING_DOMAINS = 50  # limite domini fratelli restituiti
CRTSH_TIMEOUT = 15.0      # timeout HTTP in secondi

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def query_crtsh(domain: str, client: httpx.AsyncClient) -> dict:
    """Interroga crt.sh per i certificati di *domain*.

    Args:
        domain: Dominio da interrogare (es. ``"example.com"``).
        client: Client HTTP asincrono già configurato.

    Returns:
        Un dizionario con le chiavi:
        - ``sibling_domains``: lista di domini fratelli deduplicati
          (esclude *domain* stesso, max ``MAX_SIBLING_DOMAINS``)
        - ``truncated``: ``True`` se il numero reale di domini fratelli
          supera ``MAX_SIBLING_DOMAINS``
        - ``total_siblings``: conteggio reale prima del troncamento
        - ``newest_cert_days``: età in giorni del certificato più recente
        - ``oldest_cert_days``: età in giorni del certificato più vecchio
        - ``total_certs``: numero totale di certificati trovati
        - ``error``: presente solo in caso di errore, con la descrizione
    """
    # Cache check
    cached = cache_get("crtsh", domain, TTL_CRTSH)
    if cached is not None:
        return cached

    result = await _fetch_and_parse(domain, client)
    cache_set("crtsh", domain, result)
    return result


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


async def _fetch_and_parse(domain: str, client: httpx.AsyncClient) -> dict:
    """Fetch raw JSON from crt.sh and extract structured data."""
    url = f"https://crt.sh/?q={domain}&output=json"

    try:
        response = await client.get(url, timeout=CRTSH_TIMEOUT)
        response.raise_for_status()
    except httpx.TimeoutException:
        return {"error": f"crt.sh timeout after {CRTSH_TIMEOUT}s"}
    except httpx.HTTPError as exc:
        return {"error": f"crt.sh HTTP error: {exc}"}

    # Parse JSON
    try:
        data = response.json()
    except Exception:
        return {"error": "crt.sh returned invalid JSON"}

    if not isinstance(data, list):
        return {"error": f"crt.sh unexpected response type: {type(data).__name__}"}

    if len(data) == 0:
        return {
            "sibling_domains": [],
            "truncated": False,
            "total_siblings": 0,
            "newest_cert_days": None,
            "oldest_cert_days": None,
            "total_certs": 0,
        }

    return _extract_certificate_info(data, domain)


def _extract_certificate_info(certs: list[dict], domain: str) -> dict:
    """Da una lista di certificati crt.sh, estrai SAN list, età, conteggi."""
    domain_lower = domain.lower().strip(".")
    all_sans: set[str] = set()

    timestamps: list[datetime] = []

    for cert in certs:
        # Timestamp del certificato
        for ts_field in ("not_before", "entry_timestamp"):
            ts_str = cert.get(ts_field)
            if ts_str:
                try:
                    # crt.sh restituisce date in vari formati
                    ts = _parse_crtsh_timestamp(ts_str)
                    if ts:
                        timestamps.append(ts)
                        break
                except (ValueError, OverflowError):
                    pass

        # SAN list — campo name_value
        name_value = cert.get("name_value", "")
        if name_value:
            for name in name_value.split("\n"):
                name = name.strip().lower().strip(".")
                if name and name != domain_lower:
                    all_sans.add(name)

    # Dedup: escludi il dominio interrogato
    all_sans.discard(domain_lower)

    # Troncamento con flag esplicito
    total_siblings = len(all_sans)
    truncated = total_siblings > MAX_SIBLING_DOMAINS
    sibling_list = sorted(all_sans)[:MAX_SIBLING_DOMAINS]

    # Età certificati
    now = datetime.now(timezone.utc)
    newest_days = None
    oldest_days = None
    if timestamps:
        newest = max(timestamps)
        oldest = min(timestamps)
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        newest_days = (now - newest).days
        oldest_days = (now - oldest).days

    return {
        "sibling_domains": sibling_list,
        "truncated": truncated,
        "total_siblings": total_siblings,
        "newest_cert_days": newest_days,
        "oldest_cert_days": oldest_days,
        "total_certs": len(certs),
    }


def _parse_crtsh_timestamp(ts_str: str) -> datetime | None:
    """Parsa una stringa timestamp da crt.sh in datetime UTC.

    crt.sh può restituire date in questi formati:
    - ``2024-01-15T10:30:00`` (ISO 8601 senza timezone)
    - ``2024-01-15T10:30:00.123456`` (con microsecondi)
    - ``2024-01-15`` (solo data)
    """
    ts_str = ts_str.strip()
    if not ts_str:
        return None

    # Prova formato ISO con o senza microsecondi
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None
