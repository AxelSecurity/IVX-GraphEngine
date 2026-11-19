"""Cache locale su filesystem per i risultati delle query OSINT.

Ogni provider ha la propria directory sotto ``data/osint_cache/``.
La chiave è l'hash SHA-256 della query, per evitare caratteri speciali
nei nomi file.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# TTL costanti per provider (in secondi) — nominate, non magic number
# ---------------------------------------------------------------------------

TTL_RDAP = 86_400       # 24 ore — i dati WHOIS cambiano molto raramente
TTL_CTLOGS = 21_600     # 6 ore — nuovi certificati possono comparire
TTL_DNS = 3_600         # 1 ora — i record DNS possono cambiare, ma non frequentemente
TTL_IANA_BOOTSTRAP = 2_592_000  # 30 giorni — la mappatura TLD→server RDAP è stabile
TTL_ERROR = 300         # 5 minuti — esiti di errore (timeout, 5xx, rate
                        # limit, "nessun record"): spesso transitori, non
                        # vanno trattati come dati validi per ore.  Il
                        # TTL breve evita comunque di martellare una
                        # fonte già in difficoltà con analisi ravvicinate.

# ---------------------------------------------------------------------------
# Cache root
# ---------------------------------------------------------------------------

_CACHE_ROOT = Path("data/osint_cache")


def _hash_key(key: str) -> str:
    """SHA-256 esadecimale della chiave di query."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def cache_get(provider: str, key: str, ttl_seconds: int) -> Optional[dict]:
    """Recupera un valore dalla cache se presente e non scaduto.

    Args:
        provider: Nome del provider (es. ``"rdap"``, ``"ctlogs"``).
        key: Chiave di query (es. dominio).
        ttl_seconds: TTL in secondi.

    Returns:
        Il dizionario cachato, oppure ``None`` se assente o scaduto.
    """
    cache_dir = _CACHE_ROOT / provider
    cache_file = cache_dir / f"{_hash_key(key)}.json"

    if not cache_file.is_file():
        return None

    try:
        with open(cache_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None

    stored_at = data.get("_cached_at", 0)
    # Un TTL salvato con il valore (es. ``TTL_ERROR`` per gli esiti di
    # errore) può solo ACCORCIARE quello richiesto dal chiamante.
    stored_ttl = data.get("_ttl")
    effective_ttl = (
        min(ttl_seconds, stored_ttl)
        if isinstance(stored_ttl, (int, float))
        else ttl_seconds
    )
    if time.time() - stored_at > effective_ttl:
        return None

    return data.get("_payload")


def cache_set(
    provider: str,
    key: str,
    value: dict,
    ttl_seconds: Optional[int] = None,
) -> None:
    """Scrive un valore nella cache.

    Args:
        provider: Nome del provider.
        key: Chiave di query.
        value: Dizionario da cachare (viene wrappato con metadati interni).
        ttl_seconds: TTL massimo specifico di questo valore (es.
            ``TTL_ERROR`` per un esito di errore).  ``None`` → vale il
            TTL passato dal chiamante a ``cache_get``.
    """
    cache_dir = _CACHE_ROOT / provider
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{_hash_key(key)}.json"

    envelope = {
        "_cached_at": time.time(),
        "_payload": value,
    }
    if ttl_seconds is not None:
        envelope["_ttl"] = ttl_seconds

    try:
        with open(cache_file, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh, ensure_ascii=False, default=str)
    except OSError:
        # La cache non deve mai bloccare l'analisi — fallimento silenzioso
        pass
