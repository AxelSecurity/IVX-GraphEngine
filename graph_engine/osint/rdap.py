"""RDAP (Registration Data Access Protocol) — WHOIS moderno.

Bootstrap via IANA (https://data.iana.org/rdap/dns.json) per scoprire
il server RDAP corretto per ogni TLD. Nessuna mappatura hardcodata —
stesso principio del fix tldextract per i TLD a due componenti.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from graph_engine.lexical.typosquat import _registrable_domain
from graph_engine.osint.cache import TTL_IANA_BOOTSTRAP, TTL_RDAP, cache_get, cache_set

# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = 15.0  # secondi

# ---------------------------------------------------------------------------
# RDAP query pubblica
# ---------------------------------------------------------------------------


async def query_rdap(domain: str, client: httpx.AsyncClient) -> dict:
    """Interroga il server RDAP competente per *domain*.

    Args:
        domain: Dominio da interrogare (es. ``"example.com"``).
        client: Client HTTP asincrono già configurato.

    Returns:
        Dizionario con:
        - ``domain_age_days``: età del dominio in giorni, o None
        - ``registrar``: nome del registrar, o None
        - ``nameservers``: lista dei nameserver, o [] (mai None)
        - ``error``: presente solo in caso di errore
    """
    # Usa il dominio registrabile (eTLD+1) come chiave di cache e query
    reg_domain = _registrable_domain(domain)

    cached = cache_get("rdap", reg_domain, TTL_RDAP)
    if cached is not None:
        return cached

    result = await _fetch_rdap(reg_domain, client)
    cache_set("rdap", reg_domain, result)
    return result


# ---------------------------------------------------------------------------
# Bootstrap IANA
# ---------------------------------------------------------------------------


async def _get_iana_bootstrap(client: httpx.AsyncClient) -> dict:
    """Scarica (o recupera da cache) la mappatura TLD → server RDAP da IANA.

    Il file https://data.iana.org/rdap/dns.json ha questa struttura::

        {
          "services": [
            [["net", "com"], ["https://rdap.verisign.com/net/v1/"]],
            [["org"], ["https://rdap.pir.org/org/v1/"]],
            ...
          ]
        }

    Returns:
        Un dict ``{tld: [server_url, ...]}``.
    """
    cached = cache_get("iana_bootstrap", "dns.json", TTL_IANA_BOOTSTRAP)
    if cached is not None:
        return cached

    try:
        response = await client.get(IANA_BOOTSTRAP_URL, timeout=RDAP_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        # Fallback: restituiamo un dict vuoto — il chiamante gestirà
        # l'assenza del server RDAP come "TLD non supportato"
        error_result = {"_error": f"Failed to fetch IANA bootstrap: {exc}"}
        # Non cachiamo l'errore — riproviamo al prossimo tentativo
        return error_result

    tld_map: dict[str, list[str]] = {}
    for entry in data.get("services", []):
        tlds, servers = entry[0], entry[1]
        for tld in tlds:
            tld_map[tld] = servers

    cache_set("iana_bootstrap", "dns.json", tld_map)
    return tld_map


# ---------------------------------------------------------------------------
# RDAP fetch
# ---------------------------------------------------------------------------


async def _fetch_rdap(reg_domain: str, client: httpx.AsyncClient) -> dict:
    """Risolvi il server RDAP via IANA e interrogalo per *reg_domain*."""
    # 1. Bootstrap IANA
    iana_map = await _get_iana_bootstrap(client)

    if "_error" in iana_map:
        return {"error": f"RDAP bootstrap failed: {iana_map['_error']}"}

    # 2. Estrai TLD
    tld = _extract_tld(reg_domain)
    servers = iana_map.get(tld, [])

    if not servers:
        return {"error": f"No RDAP server found for TLD '{tld}'"}

    # 3. Interroga il primo server che risponde
    rdap_url = _build_rdap_url(servers[0], reg_domain)

    try:
        response = await client.get(rdap_url, timeout=RDAP_TIMEOUT)
        if response.status_code == 404:
            return {
                "domain_age_days": None,
                "registrar": None,
                "nameservers": [],
                "error": f"Domain '{reg_domain}' not found in RDAP",
            }
        response.raise_for_status()
        rdap_data = response.json()
    except httpx.TimeoutException:
        return {"error": f"RDAP timeout after {RDAP_TIMEOUT}s for '{reg_domain}'"}
    except httpx.HTTPError as exc:
        return {"error": f"RDAP HTTP error: {exc}"}
    except Exception as exc:
        return {"error": f"RDAP unexpected error: {exc}"}

    # 4. Estrai dati
    return _extract_rdap_info(rdap_data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_tld(reg_domain: str) -> str:
    """Estrai il TLD dal dominio registrabile.

    Esempi:
        ``example.com`` → ``com``
        ``example.co.uk`` → ``co.uk``
    """
    parts = reg_domain.split(".")
    if len(parts) >= 2:
        # tldextract ci dà già il suffisso corretto; qui prendiamo
        # tutto dopo il primo label del dominio registrabile
        return ".".join(parts[1:])
    return reg_domain


def _build_rdap_url(server_url: str, domain: str) -> str:
    """Costruisce l'URL RDAP per un dominio."""
    base = server_url.rstrip("/")
    return f"{base}/domain/{domain}"


def _parse_rdap_date(date_str: str) -> Optional[datetime]:
    """Parsa una data RDAP in formato ISO 8601."""
    if not date_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_rdap_info(rdap_data: dict) -> dict:
    """Estrai dati strutturati da una risposta RDAP."""
    # Data di registrazione
    creation_date = None
    for event in rdap_data.get("events", []):
        if event.get("eventAction") == "registration":
            creation_date = _parse_rdap_date(event.get("eventDate", ""))
            break

    domain_age_days = None
    if creation_date:
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        domain_age_days = (now - creation_date).days

    # Registrar
    registrar = None
    for entity in rdap_data.get("entities", []):
        if "registrar" in (role.lower() for role in entity.get("roles", [])):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                fn_items = [
                    item[3]
                    for item in vcard[1]
                    if len(item) >= 4 and item[0] == "fn"
                ]
                if fn_items:
                    registrar = fn_items[0]
            break

    # Nameserver
    nameservers = []
    for ns in rdap_data.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            nameservers.append(name.lower())

    return {
        "domain_age_days": domain_age_days,
        "registrar": registrar,
        "nameservers": nameservers,
    }
