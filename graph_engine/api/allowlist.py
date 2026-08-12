"""Tabella SQLite per allowlist/blacklist dominio.

Il confronto avviene sul dominio REGISTRABILE (eTLD+1) usando
``graph_engine.lexical.typosquat._registrable_domain`` — la stessa
funzione già usata da L1 (typosquat) e L2 (RDAP), corretta con
tldextract offline.

Pattern di accesso: aiosqlite, DDL eseguita su ogni connessione
(coerente con ``graph_engine.storage.schema`` e repository).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

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


async def _ensure_table(db_path: str) -> None:
    """Crea la tabella allowlist se non esiste già."""
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
) -> None:
    """Aggiunge (o sovrascrive) un dominio nella allowlist/blacklist.

    Args:
        domain: Dominio o URL da inserire. Viene normalizzato al dominio
                registrabile prima del salvataggio.
        list_type: ``"whitelist"`` o ``"blacklist"``.
        note: Nota opzionale (es. motivo dell'inserimento).
        added_by: Chi ha aggiunto l'entry (es. nome operatore).
        db_path: Percorso del database SQLite.

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
