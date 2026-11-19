"""API esterna sincrona — ``GET /api/v1/analyze``.

Il servizio chiamante invia un URL e riceve una risposta binaria
safe/malicious nel formato ``{"result": {...}}`` (vedi
``verdict_response``).  La route attende il completamento REALE
dell'analisi (L0→L5) e risponde sempre col verdetto finale persistito
su SQLite — nessuna deadline imposta dal modulo: la finestra di tempo è
di competenza del chiamante.

Flow della route:

    1. Auth API key OBBLIGATORIA (``X-API-Key`` / ``API_KEY``) — 503
       se nessuna chiave è configurata, 401 se errata
    2. Estrazione dell'URL dalla query string GREZZA (tutto ciò che
       segue ``url=``) + decodifica percent-encoding iterativa
    3. Allowlist/blacklist check → risposta immediata
    4. Cache 24h (``get_latest_for_url_hash``) → risposta immediata
    5. Analisi già in corso per lo stesso URL → si attende quella
       (dedup in-flight), altrimenti se ne avvia una nuova
    6. Risposta col verdetto finale dell'analisi (letto per id).  Se la
       pipeline fallisce, il runner persiste lo stato 'error' e la
       risposta è Analysis-Failed (safe, onesta).

L'analisi gira in un task registrato in ``AnalysisJobs`` e la route lo
attende tramite ``asyncio.shield``: se il client si disconnette, la
richiesta viene cancellata ma l'analisi completa comunque e il
risultato resta in cache (24h) per la chiamata successiva.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request

from graph_engine.api.allowlist import check_url_and_domain
from graph_engine.api.auth import require_api_key
from graph_engine.api.jobs import get_jobs
from graph_engine.api.verdict_response import build_verdict_response, entry_response
from graph_engine.ingestion.canonicalize import _decode_percent_iterative
from graph_engine.ingestion.pipeline import ingest
from graph_engine.models import AnalysisTarget
from graph_engine.storage.repository import (
    get_latest_for_url_hash,
    get_target_by_id,
)
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.external")

# ── Costanti ────────────────────────────────────────────────────────────────

_CACHE_TTL_HOURS = 24
_MAX_URL_LENGTH = 2048


def _status_value(target) -> str:
    status = getattr(target, "status", None)
    return status.value if hasattr(status, "value") else str(status)


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_external_router(
    db_path: str = DEFAULT_DB_PATH,
) -> APIRouter:
    """Costruisce il router dell'API esterna con dipendenze iniettate.

    Args:
        db_path: Percorso del database SQLite.
    """

    router = APIRouter()

    @router.get("/api/v1/analyze")
    async def external_analyze(request: Request):
        """Analisi sincrona di un URL.

        L'URL arriva in query string, in chiaro:
        ``GET /api/v1/analyze?url=http://example.org``.

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
        # ── 0. Auth (API key obbligatoria — 503 se non configurata) ───
        require_api_key(request)

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
        if len(target_url) > _MAX_URL_LENGTH:
            raise HTTPException(status_code=422, detail="URL troppo lungo (max 2048)")

        # ── 2. Allowlist check (URL prima, poi dominio) ────────────────
        entry = await check_url_and_domain(target_url, db_path=db_path)
        if entry is not None:
            logger.info(
                "Allowlist hit: %s (%s) → %s",
                entry["match_key"], entry["matched"], entry["list_type"],
            )
            return entry_response(entry)

        # ── 3. Cache check (24h TTL) ───────────────────────────────────
        ingested = ingest(target_url)
        url_hash = ingested["url_hash"]
        cached = await get_latest_for_url_hash(url_hash, db_path=db_path)

        if (
            cached is not None
            and _status_value(cached["target"]) == "done"
            and cached.get("verdict") is not None
        ):
            age = datetime.now(timezone.utc) - cached["target"].created_at
            if age < timedelta(hours=_CACHE_TTL_HOURS):
                logger.info("Cache hit: %s (age=%s)", target_url, age)
                return build_verdict_response(cached)

        # ── 4. Dedup in-flight, altrimenti nuova analisi ───────────────
        jobs = get_jobs(request.app)
        running = jobs.inflight(url_hash)
        if running is not None:
            target_id, task = running
            logger.info(
                "Analysis already running for %s → attach to %s",
                target_url, target_id,
            )
        else:
            target = AnalysisTarget(
                input_url=ingested["input_url"],
                canonical_url=ingested["canonical_url"],
                url_hash=url_hash,
            )
            target_id = str(target.id)
            # Nessun await tra inflight() e start(): il target viene
            # salvato "queued" DENTRO il task (save_queued), così la
            # registrazione per la dedup è atomica.  Browser condiviso
            # dal lifespan dell'app (app.state.browser_pool); senza
            # lifespan (test) il getattr dà None → browser effimero.
            task = jobs.start(
                target_url,
                target,
                url_hash=url_hash,
                save_queued=True,
                classify=True,
                db_path=db_path,
                browser_pool=getattr(request.app.state, "browser_pool", None),
            )

        # ── 5. Attesa del completamento (shield: una disconnessione del
        # client cancella SOLO questa richiesta, mai l'analisi) ─────────
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Lo stato 'error' con la pipeline_error è già stato
            # persistito dal runner — la risposta viene dal ramo
            # Analysis-Failed di build_verdict_response.
            logger.exception("Analysis failed for %s", target_id)

        # ── 6. Risposta dal risultato persistito di QUESTA analisi ─────
        data = await get_target_by_id(target_id, db_path=db_path)
        return build_verdict_response(data)

    return router
