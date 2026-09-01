"""Autenticazione dashboard/API e API key Trellix.

Decisioni utente 2026-09-01:

- **Credenziali del login multi-utente in SQLite** (tabella ``users``):
  username, hash della password (PBKDF2-HMAC-SHA256, solo stdlib) e
  ruolo (``admin``/``operator``).
- **Il login protegge la UI e TUTTE le API REST**, con le uniche
  eccezioni di ``/health`` e della route Trellix (protetta dalla sua
  API key).  Il codice statico della dashboard (``/dashboard``) resta
  servito senza login: è la SPA stessa a mostrare il form di accesso
  quando ``/auth/me`` risponde 401.
- **Sessioni in memoria** (cookie ``session`` HttpOnly/SameSite=Lax,
  TTL 12h): non persistono tra riavvii del processo — il deployment è
  single-worker, quindi una struttura in-process è sufficiente e non
  richiede pulizia sul DB.
- **API key su ``/trellix/analyze``**: obbligatoria.  Se
  ``TRELLIX_API_KEY`` non è configurata la route risponde **503
  (configurazione mancante)**, mai aperta.  Il vecchio Bearer
  ``TRELLIX_API_TOKEN`` resta accettato per retrocompatibilità.

Pattern di accesso al DB: aiosqlite, DDL eseguita su ogni connessione
(coerente con ``graph_engine.api.allowlist`` e lo storage).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

import aiosqlite
from fastapi import HTTPException

from graph_engine.config import settings
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.auth")

# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------

# Iterazioni PBKDF2-HMAC-SHA256 (OWASP suggerisce 600k; 200k è il
# compromesso scelto per non rallentare il login oltre ~0.2s su
# hardware modesto — i test lo abbassano via monkeypatch).
_PBKDF2_ITERATIONS = 200_000

SESSION_TTL_S = 12 * 3600
SESSION_COOKIE = "session"

_USERS_DDL = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
    created_at    TEXT NOT NULL
);
"""

# Sessioni in memoria: token → {"username", "role", "expires_at"}.
# Dict in-process: sicuro per il deployment single-worker su asyncio.
_sessions: dict = {}


# ---------------------------------------------------------------------------
# Hash delle password (solo stdlib)
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash PBKDF2-HMAC-SHA256 con salt casuale.

    Formato: ``pbkdf2_sha256$<iterazioni>$<salt hex>$<digest hex>`` —
    tutto ciò che serve a verificare è dentro la stringa stessa, come
    nel formato storico di Django.
    """
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verifica una password contro un hash prodotto da ``hash_password``.

    Confronto costante nel tempo (``hmac.compare_digest``); un hash
    malformato o di algoritmo sconosciuto restituisce ``False``, mai
    un'eccezione.
    """
    try:
        algo, iterations_s, salt, expected = password_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            int(iterations_s),
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Sessioni in memoria
# ---------------------------------------------------------------------------


def create_session(username: str, role: str) -> str:
    """Crea una sessione e restituisce il token da mettere nel cookie."""
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "username": username,
        "role": role,
        "expires_at": time.time() + SESSION_TTL_S,
    }
    return token


def get_session(token: Optional[str]) -> Optional[dict]:
    """Risolve un token di sessione; scaduto o sconosciuto → ``None``."""
    if token is None:
        return None
    session = _sessions.get(token)
    if session is None:
        return None
    if session["expires_at"] < time.time():
        _sessions.pop(token, None)
        return None
    return session


def delete_session(token: Optional[str]) -> None:
    """Invalida una sessione (logout)."""
    if token is not None:
        _sessions.pop(token, None)


def revoke_user_sessions(username: str) -> None:
    """Invalida TUTTE le sessioni di un utente (es. alla cancellazione)."""
    stale = [
        token
        for token, session in _sessions.items()
        if session["username"] == username
    ]
    for token in stale:
        _sessions.pop(token, None)


def read_session_cookie(request) -> Optional[str]:
    """Estrae il token di sessione dal cookie, senza dipendenze extra.

    La lettura manuale evita di aggiungere una libreria (es. ``itsdangerous``)
    per il solo parsing: il formato del cookie di sessione è sotto il
    nostro controllo.
    """
    header = request.headers.get("cookie", "")
    for part in header.split(";"):
        name, sep, value = part.strip().partition("=")
        if name == SESSION_COOKIE and sep:
            return value
    return None


# ---------------------------------------------------------------------------
# Utenti su SQLite
# ---------------------------------------------------------------------------


async def _ensure_table(db_path: str) -> None:
    """Crea la tabella ``users`` se non esiste già."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(_USERS_DDL)


async def _get_user(db_path: str, username: str) -> Optional[dict]:
    """Legge la riga utente (senza esporre l'hash al chiamante esterno)."""
    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT username, password_hash, role, created_at "
            "FROM users WHERE username = ?",
            (username,),
        )
        row = await cur.fetchone()
    if row is None:
        return None
    return dict(row)


async def authenticate(
    db_path: str,
    username: str,
    password: str,
) -> Optional[dict]:
    """Verifica le credenziali di un utente.

    Returns:
        ``{"username", "role"}`` se valide, ``None`` altrimenti — stesso
        esito per utente inesistente e password errata (niente oracle).
    """
    user = await _get_user(db_path, username)
    if user is None:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return {"username": user["username"], "role": user["role"]}


async def list_users(db_path: str) -> list:
    """Elenca gli utenti (senza hash), ordinati per username."""
    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT username, role, created_at FROM users ORDER BY username"
        )
        rows = await cur.fetchall()
    return [
        {
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


async def create_user(
    db_path: str,
    username: str,
    password: str,
    role: str = "operator",
) -> None:
    """Crea un utente.

    Raises:
        ValueError: Se ``role`` non è valido o lo username esiste già.
    """
    if role not in ("admin", "operator"):
        raise ValueError(f"role deve essere 'admin' o 'operator', non '{role}'")
    username = username.strip()
    if not username:
        raise ValueError("username vuoto")
    if not password:
        raise ValueError("password vuota")

    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        try:
            await conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    username,
                    hash_password(password),
                    role,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        except aiosqlite.IntegrityError:
            raise ValueError(f"Utente '{username}' già esistente") from None
        await conn.commit()

    logger.info("Utente creato: %s (role=%s)", username, role)


async def delete_user(db_path: str, username: str) -> bool:
    """Cancella un utente e revoca le sue sessioni attive.

    Returns:
        ``True`` se l'utente è stato trovato e cancellato.
    """
    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        cur = await conn.execute(
            "DELETE FROM users WHERE username = ?", (username,)
        )
        await conn.commit()
        removed = cur.rowcount > 0
    if removed:
        revoke_user_sessions(username)
        logger.info("Utente cancellato: %s", username)
    return removed


async def set_password(db_path: str, username: str, password: str) -> bool:
    """Reimposta la password di un utente (e ne revoca le sessioni).

    Returns:
        ``True`` se l'utente esiste, ``False`` altrimenti.
    """
    if not password:
        raise ValueError("password vuota")
    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        cur = await conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hash_password(password), username),
        )
        await conn.commit()
        updated = cur.rowcount > 0
    if updated:
        revoke_user_sessions(username)
    return updated


async def update_user(
    db_path: str,
    username: str,
    password: Optional[str] = None,
    role: Optional[str] = None,
) -> Optional[dict]:
    """Aggiorna password e/o ruolo di un utente; revoca le sessioni se
    qualcosa è cambiato (il ruolo nella sessione in memoria diventerebbe
    stantio).

    Returns:
        ``{"username", "role"}`` con lo stato finale, ``None`` se
        l'utente non esiste.

    Raises:
        ValueError: ruolo non valido o password vuota.
    """
    if role is not None and role not in ("admin", "operator"):
        raise ValueError(f"role deve essere 'admin' o 'operator', non '{role}'")
    if password is not None and not password:
        raise ValueError("password vuota")

    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute(
            "SELECT username, role FROM users WHERE username = ?", (username,)
        )
        row = await cur.fetchone()
        if row is None:
            return None
        final_role = role if role is not None else row["role"]
        if password is not None:
            await conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(password), username),
            )
        if role is not None and role != row["role"]:
            await conn.execute(
                "UPDATE users SET role = ? WHERE username = ?",
                (role, username),
            )
        await conn.commit()

    if password is not None or (role is not None and role != row["role"]):
        revoke_user_sessions(username)
        logger.info(
            "Utente aggiornato: %s (role=%s%s)",
            username,
            final_role,
            ", password cambiata" if password is not None else "",
        )
    return {"username": username, "role": final_role}


async def ensure_bootstrap_admin(db_path: str) -> None:
    """Crea l'amministratore iniziale se la tabella utenti è vuota.

    Credenziali da ``DASHBOARD_ADMIN_USER``/``DASHBOARD_ADMIN_PASSWORD``
    se impostate; altrimenti utente ``admin`` con password casuale
    STAMPATA NEL LOG (unica via d'accesso al primo login — visibile con
    ``docker compose logs``).  Idempotente: con utenti già presenti non
    fa nulla.
    """
    await _ensure_table(db_path)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        cur = await conn.execute("SELECT COUNT(*) FROM users")
        (count,) = await cur.fetchone()
    if count > 0:
        return

    username = (settings.dashboard_admin_user or "admin").strip() or "admin"
    password = settings.dashboard_admin_password
    if password:
        await create_user(db_path, username, password, "admin")
        logger.info(
            "Admin bootstrap '%s' creato dalle variabili d'ambiente", username
        )
    else:
        password = secrets.token_urlsafe(12)
        await create_user(db_path, username, password, "admin")
        logger.warning(
            "Nessuna DASHBOARD_ADMIN_PASSWORD impostata: admin bootstrap "
            "'%s' con password generata — %s (cambiarla al primo accesso)",
            username,
            password,
        )


# ---------------------------------------------------------------------------
# API key Trellix
# ---------------------------------------------------------------------------


def require_trellix_api_key(request) -> None:
    """Autentica la route Trellix con ``X-API-Key`` (o Bearer legacy).

    Decisione utente 2026-09-01: la route NON deve mai restare aperta.
    Se nessuna credenziale è configurata → **503** (configurazione
    mancante, l'operatore deve valorizzare ``TRELLIX_API_KEY``); se è
    configurata ma la richiesta non presenta la credenziale giusta →
    **401**.

    Raises:
        HTTPException: 503 senza chiave configurata, 401 con chiave
            mancante o errata.
    """
    api_key = settings.trellix_api_key
    legacy_token = settings.trellix_api_token

    if not api_key and not legacy_token:
        raise HTTPException(
            status_code=503,
            detail=(
                "Endpoint Trellix non configurato: manca TRELLIX_API_KEY "
                "nell'ambiente del server"
            ),
        )

    provided_key = request.headers.get("X-API-Key", "")
    if api_key and hmac.compare_digest(provided_key, api_key):
        return

    auth_header = request.headers.get("Authorization", "")
    if legacy_token and _bearer_matches(auth_header, legacy_token):
        return

    raise HTTPException(status_code=401, detail="Unauthorized")


def _bearer_matches(auth_header: str, expected_token: str) -> bool:
    """Verifica un header ``Authorization: Bearer <token>`` (legacy)."""
    if not auth_header.startswith("Bearer "):
        return False
    provided = auth_header[len("Bearer "):]
    return hmac.compare_digest(provided, expected_token)
