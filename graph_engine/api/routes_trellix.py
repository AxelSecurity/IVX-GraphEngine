"""Route sincrona Trellix IVX — ``GET /trellix/analyze``.

Trellix invia un URL e si aspetta una risposta binaria safe/malicious.
Questa route attende il completamento REALE dell'analisi (L0→L5) e
risponde sempre col verdetto finale persistito su SQLite — nessuna
deadline imposta dal modulo: la finestra di tempo è di competenza
dell'infrastruttura a monte (Front Door / Trellix), non di qui.  Il
budget dell'esplorazione resta quello PIENO del modulo (timebox
interni del BFS inclusi): l'analisi gira "in tranquillità".

Flow della route:

    1. Auth API key OBBLIGATORIA (``X-API-Key`` / ``TRELLIX_API_KEY``;
       Bearer ``TRELLIX_API_TOKEN`` accettato per retrocompatibilità) —
       503 se nessuna credenziale è configurata, 401 se errata
    2. Estrazione dell'URL dalla query string GREZZA (tutto ciò che
       segue ``url=``) + decodifica percent-encoding iterativa
    3. Allowlist/blacklist check → risposta immediata
    4. Cache 24h (``get_latest_for_url_hash``) → risposta immediata
    5. Analisi completa + risposta col verdetto finale.  Se la
       pipeline fallisce, il runner persiste lo stato 'error' e la
       risposta è Analysis-Failed (safe, onesta).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request

from graph_engine.api.allowlist import check_url_and_domain
from graph_engine.api.auth import require_trellix_api_key
from graph_engine.api.pipeline_runner import run_full_analysis
from graph_engine.api.trellix_verdict import build_trellix_response, entry_response
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
) -> APIRouter:
    """Costruisce il router Trellix con dipendenze iniettate.

    Args:
        db_path: Percorso del database SQLite.
    """

    router = APIRouter()

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
        # ── 0. Auth (API key obbligatoria — 503 se non configurata) ───
        require_trellix_api_key(request)

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

        # ── 2. Allowlist check (URL prima, poi dominio) ────────────────
        entry = await check_url_and_domain(target_url, db_path=db_path)
        if entry is not None:
            logger.info(
                "Trellix allowlist hit: %s (%s) → %s",
                entry["match_key"], entry["matched"], entry["list_type"],
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

        # ── 4. Analisi sincrona ─────────────────────────────────────────

        # 4a. Pre-crea il target come "queued" (pattern POST /analyses)
        target = AnalysisTarget(
            input_url=ingested["input_url"],
            canonical_url=ingested["canonical_url"],
            url_hash=url_hash,
        )
        await save_target(target, [], [], [], None, db_path=db_path)

        # 4b. Esegue la pipeline e ATTENDE il completamento reale —
        # nessuna deadline imposta dal modulo: la risposta porta sempre
        # il verdetto finale.  L'unica finestra di tempo è quella
        # gestita a monte (Front Door / Trellix), non qui — il budget
        # resta quello PIENO del runner (timebox interni del BFS
        # inclusi).
        #
        # Browser condiviso dal lifespan dell'app
        # (app.state.browser_pool): nessun launch Chromium per
        # richiesta.  Nei test con router standalone (nessun lifespan
        # eseguito) il getattr dà None e la pipeline degrada al
        # browser effimero — invariato.
        #
        # Task creato esplicitamente: se il client si disconnette
        # mentre l'analisi gira, questa completa comunque e il
        # risultato resta in cache (24h) per la richiesta successiva.
        task = asyncio.create_task(
            run_full_analysis(
                target_url,
                classify=True,
                target=target,
                db_path=db_path,
                browser_pool=getattr(request.app.state, "browser_pool", None),
            )
        )
        try:
            await task
        except Exception:
            # Lo stato 'error' con la pipeline_error è già stato
            # persistito dal runner — qui consumiamo l'eccezione e la
            # risposta viene dal ramo Analysis-Failed di
            # build_trellix_response.
            logger.exception("Trellix analysis failed for %s", target.id)

        # 4c. Risponde col risultato persistito su SQLite
        data = await get_latest_for_url_hash(url_hash, db_path=db_path)
        return build_trellix_response(data)

    return router
