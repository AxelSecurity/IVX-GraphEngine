"""Route sincrona compatibile Trellix IVX — ``GET /trellix/analyze``.

Trellix invia URL a un endpoint sincrono e si aspetta una risposta
binaria safe/malicious entro ~60 secondi.  Questo modulo implementa
il pattern **fire-and-continue**: l'analisi parte in background, e
se non completa entro la finestra di tempo, rispondiamo comunque con
un verdetto "safe" onesto (Analysis-Incomplete) SENZA cancellare il
task — che continua in background e persiste il risultato su SQLite
per la prossima richiesta (cache 24h).

Flow della route:

    1. Auth Bearer opzionale (``TRELLIX_API_TOKEN``)
    2. Estrazione dell'URL dalla query string GREZZA (tutto ciò che
       segue ``url=``) + decodifica percent-encoding iterativa
    3. Allowlist/blacklist check → risposta immediata
    4. Cache 24h (``get_latest_for_url_hash``) → risposta immediata
    5. Fire-and-continue con ``asyncio.wait([task], timeout=48)``
       — NON cancella il task se scade il timeout
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Header, HTTPException, Request

from graph_engine.api.allowlist import check_domain
from graph_engine.api.fast_profile import (
    FAST_BUDGET,
    FAST_CAPTCHA_WAIT_S,
    FAST_L2_TIMEOUT_S,
    FAST_L3_TIMEOUT_S,
    FAST_PAGE_TIMEOUT_MS,
    FAST_SETTLE_MAX_WAIT_S,
    FAST_TOP_N_ACTIONS,
    TRELLIX_RESPONSE_TIMEOUT_S,
)
from graph_engine.api.pipeline_runner import run_full_analysis
from graph_engine.api.trellix_verdict import build_trellix_response, entry_response
from graph_engine.config import settings
from graph_engine.ingestion.canonicalize import _decode_percent_iterative
from graph_engine.models import AnalysisTarget
from graph_engine.storage.repository import get_latest_for_url_hash, save_target
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.trellix")

# ── Costanti ────────────────────────────────────────────────────────────────

_CACHE_TTL_HOURS = 24


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_trellix_router(
    db_path: str = DEFAULT_DB_PATH,
    wait_timeout_s: float = TRELLIX_RESPONSE_TIMEOUT_S,
) -> APIRouter:
    """Costruisce il router Trellix con dipendenze iniettate.

    Args:
        db_path: Percorso del database SQLite.
        wait_timeout_s: Timeout di attesa per il task in secondi
                        (iniettabile per i test).
    """

    router = APIRouter()

    def _on_task_done(task: asyncio.Task) -> None:
        """Consuma l'eccezione del background task per evitare
        ``Task exception was never retrieved``.  Lo stato 'error' è già
        stato persistito su SQLite dal runner."""
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        if exc is not None:
            logger.error("Background Trellix analysis failed: %s", exc)

    # ──────────────────────────────────────────────────────────────────────
    # GET /trellix/analyze
    # ──────────────────────────────────────────────────────────────────────

    @router.get("/trellix/analyze")
    async def trellix_analyze(request: Request):
        """Endpoint sincrono compatibile Trellix.

        Trellix passa l'URL in query string, in chiaro:
        ``GET /trellix/analyze?url=http://example.org``.

        Il parametro NON viene letto col parsing standard di FastAPI:
        un URL reale può contenere ``&``, ``?`` e ``=`` propri (es. i
        link di sicurezza email con query string lunghe) e il parsing
        standard li tratterebbe come parametri separati, TRONCANDO
        l'URL da analizzare.  Prendiamo quindi TUTTO ciò che segue
        ``url=`` dalla query string grezza, poi decodifichiamo il
        percent-encoding iterativamente: un URL in chiaro resta
        invariato, uno encodato (anche più volte) converge alla forma
        leggibile.
        """
        # ── 0. Auth ────────────────────────────────────────────────────
        token = settings.trellix_api_token
        if token:
            auth_header = request.headers.get("Authorization", "")
            if not _check_token(auth_header, token):
                raise HTTPException(status_code=401, detail="Unauthorized")

        # ── 1. Estrazione URL dalla query string grezza ────────────────
        raw_query = request.url.query or ""
        if "url=" not in raw_query:
            raise HTTPException(
                status_code=422, detail="Parametro 'url' mancante nella query string",
            )
        target_url_raw = raw_query.split("url=", 1)[1]

        # Decodifica iterativa (stessa logica della canonicalizzazione
        # L0): un URL in chiaro non contiene % → resta identico.
        target_url = _decode_percent_iterative(target_url_raw.strip())
        if not target_url:
            raise HTTPException(status_code=422, detail="URL vuoto dopo decoding")
        if len(target_url) > 2048:
            raise HTTPException(status_code=422, detail="URL troppo lungo (max 2048)")

        # ── 2. Allowlist check ─────────────────────────────────────────
        hostname = urlparse(target_url).hostname
        if hostname:
            entry = await check_domain(hostname, db_path=db_path)
            if entry is not None:
                logger.info(
                    "Trellix allowlist hit: %s → %s",
                    hostname, entry["list_type"],
                )
                return entry_response(entry)

        # ── 3. Cache check (24h TTL) ───────────────────────────────────
        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest(target_url)
        url_hash = ingested["url_hash"]
        cached = await get_latest_for_url_hash(url_hash, db_path=db_path)

        if cached is not None:
            target_status = getattr(cached["target"], "status", None)
            status_val = (
                target_status.value
                if hasattr(target_status, "value")
                else str(target_status)
            )

            # Cache hit solo se done + verdict presente + creato < 24h fa
            if status_val == "done" and cached.get("verdict") is not None:
                created_at = cached["target"].created_at
                age = datetime.now(timezone.utc) - created_at
                if age < timedelta(hours=_CACHE_TTL_HOURS):
                    logger.info(
                        "Trellix cache hit: %s (age=%s)", target_url, age,
                    )
                    return build_trellix_response(cached)

        # ── 4. Fire-and-continue ───────────────────────────────────────

        # 4a. Pre-crea il target come "queued" (pattern POST /analyses)
        target = AnalysisTarget(
            input_url=ingested["input_url"],
            canonical_url=ingested["canonical_url"],
            url_hash=url_hash,
        )
        await save_target(target, [], [], [], None, db_path=db_path)

        # 4b. Lancia l'analisi in background
        task = asyncio.create_task(
            run_full_analysis(
                target_url,
                budget=FAST_BUDGET,
                classify=True,
                target=target,
                db_path=db_path,
                top_n_actions=FAST_TOP_N_ACTIONS,
                captcha_wait_s=FAST_CAPTCHA_WAIT_S,
                l2_timeout_s=FAST_L2_TIMEOUT_S,
                l3_timeout_s=FAST_L3_TIMEOUT_S,
                settle_max_wait_s=FAST_SETTLE_MAX_WAIT_S,
                page_timeout_ms=FAST_PAGE_TIMEOUT_MS,
                capture_artifacts=False,
            )
        )
        task.add_done_callback(_on_task_done)

        # 4c. Attendi con asyncio.wait (NON wait_for — NON cancella!)
        done, pending = await asyncio.wait({task}, timeout=wait_timeout_s)
        timed_out = task in pending

        # 4d. Leggi lo stato corrente da SQLite
        data = await get_latest_for_url_hash(url_hash, db_path=db_path)

        if timed_out:
            logger.info(
                "Trellix analysis %s still running after %.0fs — "
                "responding timed_out, task continues in background",
                target.id, wait_timeout_s,
            )

        return build_trellix_response(data, timed_out=timed_out)

    return router


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _check_token(auth_header: str, expected_token: str) -> bool:
    """Verifica il token Bearer con confronto costante nel tempo.

    Args:
        auth_header: Valore dell'header ``Authorization``.
        expected_token: Token configurato nell'ambiente.

    Returns:
        ``True`` se il token è valido.
    """
    if not auth_header.startswith("Bearer "):
        return False
    provided = auth_header[7:]  # len("Bearer ") == 7
    return secrets.compare_digest(provided, expected_token)
