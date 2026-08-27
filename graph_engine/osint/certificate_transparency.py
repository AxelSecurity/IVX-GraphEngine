"""Certificate Transparency — domini fratelli di campagna.

Provider primario: crt.sh (API pubblica, una sola richiesta con tutta
la SAN list).  Fallback: ctlogs.dev quando crt.sh non risponde, in due
modalità:

- **API con chiave** (``https://api.ctlogs.dev``, chiave su richiesta):
  il JSON della ricerca non include la SAN list, quindi i SAN vengono
  aggregati interrogando ``/v1/cert/{id}`` per i certificati più
  recenti.
- **Anonima** (senza chiave): endpoint pubblico
  ``https://ctlogs.dev/search?output=json`` — nessuna SAN list
  disponibile, quindi niente sibling; restano disponibili date e
  conteggi della cronologia certificati.

Il segnale a più alto valore è la **SAN list deduplicata**: i domini
che condividono un certificato con il dominio target sono potenziali
domini fratelli della stessa campagna di phishing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from graph_engine.config import settings
from graph_engine.osint.cache import TTL_CRTSH, cache_get, cache_set

# ---------------------------------------------------------------------------
# Limiti
# ---------------------------------------------------------------------------

MAX_SIBLING_DOMAINS = 50  # limite domini fratelli restituiti
CRTSH_TIMEOUT = 15.0      # timeout HTTP in secondi

CTLOGS_API_URL = "https://api.ctlogs.dev"

# Quanti certificati interrogare in dettaglio (``/v1/cert/{id}``) per la
# SAN list nel fallback: la risposta della ricerca è ordinata per
# ``not_before`` discendente, quindi i primi N sono i più recenti — i
# più rilevanti per una campagna di phishing attiva.  Ogni richiesta
# costa 1 unit della quota mensile della chiave; il risultato è cachato
# con lo stesso TTL di crt.sh.
CTLOGS_MAX_CERT_DETAILS = 25

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def query_crtsh(
    domain: str,
    client: httpx.AsyncClient,
    timeout: float | None = None,
) -> dict:
    """Interroga crt.sh per i certificati di *domain*.

    Args:
        domain: Dominio da interrogare (es. ``"example.com"``).
        client: Client HTTP asincrono già configurato.
        timeout: Timeout HTTP in secondi. Se ``None``, usa
                 ``CRTSH_TIMEOUT`` (15s).

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

    result = await _fetch_and_parse(domain, client, timeout=timeout)
    cache_set("crtsh", domain, result)
    return result


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


async def _fetch_and_parse(
    domain: str,
    client: httpx.AsyncClient,
    timeout: float | None = None,
) -> dict:
    """Fetch raw JSON from crt.sh and extract structured data."""
    url = f"https://crt.sh/?q={domain}&output=json"
    effective_timeout = timeout if timeout is not None else CRTSH_TIMEOUT

    try:
        response = await client.get(url, timeout=effective_timeout)
        response.raise_for_status()
    except httpx.TimeoutException:
        return {"error": f"crt.sh timeout after {effective_timeout}s"}
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


# ---------------------------------------------------------------------------
# Fallback: ctlogs.dev REST API (contratto verificato su api.ctlogs.dev)
# ---------------------------------------------------------------------------


async def query_ctlogs(
    domain: str,
    client: httpx.AsyncClient,
    timeout: float | None = None,
) -> dict:
    """Fallback a ctlogs.dev quando crt.sh non risponde.

    Due modalità:

    - **API con chiave** (``settings.ctlogs_configured``):
      ``/v1/domain/{host}`` + dettagli ``/v1/cert/{id}`` → SAN completi
      (``san_dns``) → ``sibling_domains`` come crt.sh.
    - **Anonima** (senza chiave): endpoint pubblico
      ``https://ctlogs.dev/search?q=<domain>&output=json`` — nessuna
      SAN list disponibile, quindi ``sibling_domains`` resta vuoto;
      date e conteggi sono comunque disponibili.

    Contratto di ritorno (stesso di ``query_crtsh``, più ``source`` e
    ``mode``):

    - ``sibling_domains``: SAN aggregati dei ``CTLOGS_MAX_CERT_DETAILS``
      certificati più recenti (solo modalità API; la ricerca è ordinata
      per ``not_before`` discendente)
    - ``newest_cert_days``: sempre noto (prima riga = più recente)
    - ``oldest_cert_days``/``total_certs``: ``None`` quando la risposta
      è paginata (``has_next``) — l'età vera del dominio non è nota
      senza scaricare tutte le pagine; mai inventare un valore
    - ``mode``: ``"api"`` o ``"anonymous"``
    - ``error``: presente solo in caso di errore

    La cache è separata per modalità: quando la chiave arriva, un
    risultato anonimo (senza sibling) non viene riusato dall'API.
    """
    api_mode = settings.ctlogs_configured
    cache_provider = "ctlogs" if api_mode else "ctlogs_anon"

    cached = cache_get(cache_provider, domain, TTL_CRTSH)
    if cached is not None:
        return cached

    result = await _fetch_and_parse_ctlogs(domain, client, timeout=timeout)
    cache_set(cache_provider, domain, result)
    return result


async def _fetch_and_parse_ctlogs(
    domain: str,
    client: httpx.AsyncClient,
    timeout: float | None = None,
) -> dict:
    """Ricerca certificati + (solo API) dettagli ``/v1/cert/{id}``.

    La ricerca restituisce righe ``{id, match, not_before, not_after,
    serial_hex, issuer, key_algo, san_count}`` SENZA la SAN list (forma
    identica tra endpoint pubblico e ``/v1/domain/{host}``, verificata
    live su entrambi); i SAN completi stanno nel dettaglio (``san_dns``),
    recuperato in parallelo per i primi ``CTLOGS_MAX_CERT_DETAILS`` id
    SOLO in modalità API.
    """
    effective_timeout = timeout if timeout is not None else CRTSH_TIMEOUT
    api_mode = settings.ctlogs_configured
    headers = (
        {"Authorization": f"Bearer {settings.ctlogs_api_key}"}
        if api_mode
        else None
    )

    # ── 1. Ricerca ─────────────────────────────────────────────────────
    if api_mode:
        url = f"{CTLOGS_API_URL}/v1/domain/{domain}"
    else:
        url = f"https://ctlogs.dev/search?q={domain}&output=json"
    try:
        response = await client.get(
            url, timeout=effective_timeout, headers=headers
        )
        response.raise_for_status()
    except httpx.TimeoutException:
        return {"error": f"ctlogs.dev timeout after {effective_timeout}s"}
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401 and api_mode:
            return {"error": "ctlogs.dev auth error: API key invalid/revoked"}
        if status == 429:
            return {"error": "ctlogs.dev rate limit or quota exhausted (429)"}
        return {"error": f"ctlogs.dev HTTP error {status}"}
    except httpx.HTTPError as exc:
        return {"error": f"ctlogs.dev HTTP error: {exc}"}

    try:
        data = response.json()
    except Exception:
        return {"error": "ctlogs.dev returned invalid JSON"}

    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return {
            "error": f"ctlogs.dev unexpected response type: "
            f"{type(data).__name__}"
        }

    if len(rows) == 0:
        return {
            "sibling_domains": [],
            "truncated": False,
            "total_siblings": 0,
            "newest_cert_days": None,
            "oldest_cert_days": None,
            "total_certs": 0,
            "source": "ctlogs.dev",
            "mode": "api" if api_mode else "anonymous",
        }

    has_next = bool(data.get("has_next"))

    # ── 2. Età dei certificati ─────────────────────────────────────────
    # Righe ordinate per not_before discendente: la prima è la più
    # recente (newest sempre affidabile).  La più vecchia è affidabile
    # SOLO se la risposta non è paginata — altrimenti None (onestà:
    # un oldest falsato produrrebbe un falso "dominio appena creato").
    timestamps: list[datetime] = []
    for row in rows:
        ts = _parse_ctlogs_timestamp(row.get("not_before"))
        if ts is not None:
            timestamps.append(ts)

    now = datetime.now(timezone.utc)
    newest_days = None
    oldest_days = None
    if timestamps:
        newest_days = (now - max(timestamps)).days
        if not has_next:
            oldest_days = (now - min(timestamps)).days

    # ── 3. SAN list dai dettagli, in parallelo (SOLO modalità API) ────
    # L'endpoint pubblico non espone la SAN list in JSON: senza chiave
    # niente sibling (la cronologia certificati resta comunque nota).
    domain_lower = domain.lower().strip(".")
    all_sans: set[str] = set()
    if api_mode:
        ids = [
            str(row["id"])
            for row in rows[:CTLOGS_MAX_CERT_DETAILS]
            if isinstance(row, dict) and row.get("id")
        ]
        detail_results = await asyncio.gather(
            *(_fetch_ctlogs_cert_sans(cid, client, effective_timeout, headers)
              for cid in ids),
            return_exceptions=True,
        )
        for result in detail_results:
            if isinstance(result, list):
                for name in result:
                    name = str(name).strip().lower().strip(".")
                    if name and name != domain_lower:
                        all_sans.add(name)

    # Dedup: escludi il dominio interrogato
    all_sans.discard(domain_lower)

    total_siblings = len(all_sans)
    truncated = total_siblings > MAX_SIBLING_DOMAINS
    sibling_list = sorted(all_sans)[:MAX_SIBLING_DOMAINS]

    return {
        "sibling_domains": sibling_list,
        "truncated": truncated,
        "total_siblings": total_siblings,
        "newest_cert_days": newest_days,
        "oldest_cert_days": oldest_days,
        # Se la risposta è paginata il conteggio reale non è noto:
        # None (mai un numero inventato).
        "total_certs": None if has_next else len(rows),
        "source": "ctlogs.dev",
        "mode": "api" if api_mode else "anonymous",
    }


async def _fetch_ctlogs_cert_sans(
    cert_id: str,
    client: httpx.AsyncClient,
    timeout: float,
    headers: dict,
) -> list[str] | None:
    """Recupera la SAN list (``san_dns``) di un certificato.

    Ritorna ``None`` per ogni dettaglio non recuperabile (best effort:
    un singolo certificato rotto non deve far fallire l'aggregazione).
    """
    url = f"{CTLOGS_API_URL}/v1/cert/{cert_id}"
    try:
        response = await client.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        data = response.json()
        san_dns = data.get("san_dns") if isinstance(data, dict) else None
        if isinstance(san_dns, list):
            return [str(s) for s in san_dns]
        return None
    except (httpx.HTTPError, ValueError):
        return None


def _parse_ctlogs_timestamp(ts_str: Any) -> datetime | None:
    """Parsa un timestamp ISO-8601 di ctlogs.dev (es. ``2026-07-29T22:10:08Z``)."""
    if not isinstance(ts_str, str):
        return None
    ts_str = ts_str.strip()
    if not ts_str:
        return None
    try:
        # Python 3.9: fromisoformat non accetta 'Z' → +00:00
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None
