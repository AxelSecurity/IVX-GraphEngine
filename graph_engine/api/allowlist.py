"""Tabelle SQLite per allowlist/blacklist di DOMINI e URL.

Il confronto sui domini avviene sul dominio REGISTRABILE (eTLD+1)
usando ``graph_engine.lexical.typosquat._registrable_domain`` — la
stessa funzione già usata da L1 (typosquat) e L2 (RDAP), corretta con
tldextract offline.

Il confronto sugli URL avviene sulla URL normalizzata L0 SENZA query e
frammento (scheme+host+path): un cambio di parametro di tracciamento
non fa uscire l'URL dalla lista (decisione utente 2026-09-01).

Priorità (decisione utente 2026-09-01): in caso di conflitto tra i due
livelli vince il match più specifico — URL > dominio.  Vedi
``check_url_and_domain``.

Pattern di accesso: aiosqlite, DDL eseguita su ogni connessione
(coerente con ``graph_engine.storage.schema`` e repository).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import aiosqlite

from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.allowlist")

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_ALLOWLIST_DDL = """
CREATE TABLE IF NOT EXISTS allowlist_blacklist (
    domain    TEXT PRIMARY KEY,
    list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
    note      TEXT,
    added_by  TEXT,
    added_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist_blacklist_url (
    url       TEXT PRIMARY KEY,
    list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
    note      TEXT,
    added_by  TEXT,
    added_at  TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Helpers privati
# ---------------------------------------------------------------------------


def _normalize_domain(domain_or_url: str) -> str:
    """Estrae il dominio registrabile (eTLD+1) da un URL o hostname.

    ``_registrable_domain()`` si aspetta un **hostname**, non un URL.
    Passare un URL intero (es. ``"https://login.example.com/x"``)
    restituirebbe la stringa intera come fallback (nessun suffisso TLD
    riconosciuto).  Estraiamo quindi l'hostname con ``urlparse`` prima
    di chiamare la funzione.
    """
    from urllib.parse import urlparse

    from graph_engine.lexical.typosquat import _registrable_domain

    raw = domain_or_url.strip()
    hostname = urlparse(raw).hostname or raw.lower().rstrip(".")
    return _registrable_domain(hostname)


def _normalize_url(url: str) -> str:
    """Normalizza una URL per il confronto: canonicalizzazione L0 senza query/frammento.

    Compone ``canonicalize_and_hash`` (lowercase, IDN, percent-decoding,
    path vuoto → ``"/"``) con lo strip di query e frammento via
    ``urlparse``/``urlunparse``: resta scheme+host+path.

    Raises:
        ValueError: Se la URL non è http/https (scheme mancante o diverso).
    """
    from graph_engine.ingestion.canonicalize import canonicalize_and_hash

    canonical, _ = canonicalize_and_hash(url.strip())
    parsed = urlparse(canonical)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL deve essere http o https, non '{parsed.scheme}'"
        )
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


async def _ensure_table(db_path: str) -> None:
    """Crea le tabelle allowlist (domini e URL) se non esistono già."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(_ALLOWLIST_DDL)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def add_entry(
    domain: str,
    list_type: str,
    note: str | None = None,
    added_by: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> str:
    """Aggiunge (o sovrascrive) un dominio nella allowlist/blacklist.

    Args:
        domain: Dominio o URL da inserire. Viene normalizzato al dominio
                registrabile prima del salvataggio.
        list_type: ``"whitelist"`` o ``"blacklist"``.
        note: Nota opzionale (es. motivo dell'inserimento).
        added_by: Chi ha aggiunto l'entry (es. nome operatore).
        db_path: Percorso del database SQLite.

    Returns:
        Il dominio registrabile normalizzato effettivamente salvato.

    Raises:
        ValueError: Se ``list_type`` non è valido.
    """
    if list_type not in ("whitelist", "blacklist"):
        raise ValueError(
            f"list_type deve essere 'whitelist' o 'blacklist', "
            f"non '{list_type}'"
        )

    normalized = _normalize_domain(domain)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute(
            "INSERT OR REPLACE INTO allowlist_blacklist "
            "(domain, list_type, note, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                normalized,
                list_type,
                note,
                added_by,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await conn.commit()

    logger.info("Allowlist entry %s → %s (by %s)", normalized, list_type, added_by)
    return normalized


async def remove_entry(
    domain: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """Rimuove un dominio dalla allowlist/blacklist.

    Args:
        domain: Dominio o URL da rimuovere (normalizzato automaticamente).
        db_path: Percorso del database SQLite.

    Returns:
        ``True`` se l'entry è stata trovata e rimossa, ``False`` altrimenti.
    """
    normalized = _normalize_domain(domain)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        cur = await conn.execute(
            "DELETE FROM allowlist_blacklist WHERE domain = ?",
            (normalized,),
        )
        await conn.commit()
        return cur.rowcount > 0


async def check_domain(
    domain: str,
    db_path: str = DEFAULT_DB_PATH,
) -> dict | None:
    """Verifica se *domain* appare nella allowlist/blacklist.

    Il confronto avviene sul dominio REGISTRABILE: cercare
    ``"login.example.com"`` matcha l'entry ``"example.com"``.

    Args:
        domain: Dominio o URL da verificare.
        db_path: Percorso del database SQLite.

    Returns:
        ``{"list_type": "whitelist", "note": "..."}`` se trovato,
        ``None`` se il dominio non è in nessuna lista.
    """
    normalized = _normalize_domain(domain)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT list_type, note FROM allowlist_blacklist WHERE domain = ?",
            (normalized,),
        )
        row = await cur.fetchone()

    if row is None:
        return None
    return {"list_type": row["list_type"], "note": row["note"]}


async def add_url_entry(
    url: str,
    list_type: str,
    note: str | None = None,
    added_by: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> str:
    """Aggiunge (o sovrascrive) una URL nella allowlist/blacklist.

    La URL viene normalizzata (canonicalizzazione L0 senza query e
    frammento) prima del salvataggio: ``add_url_entry(a)`` seguito da
    ``add_url_entry(b)`` con ``a``/``b`` equivalenti riscrive la stessa
    riga.

    Returns:
        La URL normalizzata effettivamente salvata.

    Raises:
        ValueError: Se ``list_type`` non è valido o la URL non è http/https.
    """
    if list_type not in ("whitelist", "blacklist"):
        raise ValueError(
            f"list_type deve essere 'whitelist' o 'blacklist', "
            f"non '{list_type}'"
        )

    normalized = _normalize_url(url)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute(
            "INSERT OR REPLACE INTO allowlist_blacklist_url "
            "(url, list_type, note, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                normalized,
                list_type,
                note,
                added_by,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await conn.commit()

    logger.info("Allowlist URL entry %s → %s (by %s)", normalized, list_type, added_by)
    return normalized


async def remove_url_entry(
    url: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """Rimuove una URL dalla allowlist/blacklist.

    Returns:
        ``True`` se l'entry è stata trovata e rimossa, ``False`` altrimenti.
    """
    normalized = _normalize_url(url)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        cur = await conn.execute(
            "DELETE FROM allowlist_blacklist_url WHERE url = ?",
            (normalized,),
        )
        await conn.commit()
        return cur.rowcount > 0


async def check_url(
    url: str,
    db_path: str = DEFAULT_DB_PATH,
) -> dict | None:
    """Verifica se *url* appare nella allowlist/blacklist URL.

    Il confronto avviene sulla URL normalizzata SENZA query/frammento:
    cercare ``"https://site.it/login?sid=abc"`` matcha l'entry
    ``"https://site.it/login"``.

    Returns:
        ``{"list_type": ..., "note": ..., "matched": "url",
        "match_key": <url normalizzata>}`` se trovata, ``None`` altrimenti.
    """
    normalized = _normalize_url(url)
    await _ensure_table(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT list_type, note FROM allowlist_blacklist_url WHERE url = ?",
            (normalized,),
        )
        row = await cur.fetchone()

    if row is None:
        return None
    return {
        "list_type": row["list_type"],
        "note": row["note"],
        "matched": "url",
        "match_key": normalized,
    }


async def check_url_and_domain(
    url: str,
    db_path: str = DEFAULT_DB_PATH,
) -> dict | None:
    """Check combinato URL + dominio: vince il match più specifico.

    Prima la lista URL (match su scheme+host+path normalizzato), poi la
    lista domini (match sul dominio registrabile).  Se entrambe
    contengono la URL, vince la URL.

    Returns:
        ``{"list_type": ..., "note": ..., "matched": "url"|"domain",
        "match_key": ...}`` se trovato, ``None`` altrimenti.
    """
    entry = await check_url(url, db_path=db_path)
    if entry is not None:
        return entry

    normalized = _normalize_domain(url)
    domain_entry = await check_domain(url, db_path=db_path)
    if domain_entry is None:
        return None
    return {
        "list_type": domain_entry["list_type"],
        "note": domain_entry["note"],
        "matched": "domain",
        "match_key": normalized,
    }


async def list_entries(
    db_path: str = DEFAULT_DB_PATH,
) -> dict:
    """Elenca tutte le entry (domini e URL) per la dashboard.

    Returns:
        ``{"domains": [{"value", "list_type", "note", "added_by",
        "added_at"}, ...], "urls": [...]}`` — le righe sono ordinate per
        valore, ``value`` è il dominio/URL normalizzato.
    """
    await _ensure_table(db_path)

    def _row_to_entry(row) -> dict:
        entry = {
            "list_type": row["list_type"],
            "note": row["note"],
            "added_by": row["added_by"],
            "added_at": row["added_at"],
        }
        entry["value"] = row["domain"] if "domain" in row.keys() else row["url"]
        return entry

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT domain, list_type, note, added_by, added_at "
            "FROM allowlist_blacklist ORDER BY domain"
        )
        domains = [_row_to_entry(row) for row in await cur.fetchall()]
        cur = await conn.execute(
            "SELECT url, list_type, note, added_by, added_at "
            "FROM allowlist_blacklist_url ORDER BY url"
        )
        urls = [_row_to_entry(row) for row in await cur.fetchall()]

    return {"domains": domains, "urls": urls}
