"""HTTP API routes — factory con db_path/artifact_root iniettabili.

L'iniezione delle dipendenze (db_path, artifact_root) permette ai test
di puntare a directory temporanee senza toccare il filesystem reale.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Optional

import aiosqlite
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse

from graph_engine.api.artifact_cleanup import remove_artifact_dirs
from graph_engine.api.pipeline_runner import DEFAULT_ARTIFACT_ROOT, run_full_analysis
from graph_engine.api.schemas import (
    AnalysesDeleteRequest,
    AnalysesDeleteResponse,
    AnalysisCreateRequest,
    AnalysisCreatedResponse,
    AnalysisGraphResponse,
    AnalysisListEntry,
    AnalysisListResponse,
    AnalysisSummaryResponse,
    ArtifactFile,
    ArtifactListing,
    HealthResponse,
    HistoryEntry,
    HistoryResponse,
    TargetSummary,
    VerdictSummary,
)
from graph_engine.budget import Budget
from graph_engine.models import AnalysisTarget, TargetStatus
from graph_engine.storage.repository import (
    count_targets,
    delete_targets,
    get_history_for_url_hash,
    get_target_by_id,
    list_targets,
    save_target,
)
from graph_engine.storage.schema import DEFAULT_DB_PATH, DDL, ensure_data_dir

logger = logging.getLogger("graph_engine.api")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

# Whitelist dei soli file che ``StateGraphExplorer._save_artifacts`` scrive
# per ogni stato — vedi get_artifact_file() più sotto.
_ARTIFACT_MEDIA_TYPES = {
    "screenshot.png": "image/png",
    "dom.html": "text/html; charset=utf-8",
    "snapshot.har": "application/json",
}


# ---------------------------------------------------------------------------
# Helper — converte un target di dominio in TargetSummary
# ---------------------------------------------------------------------------


def _to_target_summary(target: AnalysisTarget) -> TargetSummary:
    """Converte un ``AnalysisTarget`` (dominio) in ``TargetSummary`` (API)."""
    return TargetSummary(
        id=str(target.id),
        input_url=target.input_url,
        canonical_url=target.canonical_url,
        url_hash=target.url_hash,
        final_url=target.final_url,
        status=target.status.value,
        root_state_id=str(target.root_state_id) if target.root_state_id else None,
        created_at=target.created_at,
    )


def _to_verdict_summary(verdict) -> Optional[VerdictSummary]:
    """Converte un ``Verdict`` (dominio) in ``VerdictSummary`` (API)."""
    if verdict is None:
        return None
    return VerdictSummary(
        classification=verdict.classification.value
        if hasattr(verdict.classification, "value")
        else str(verdict.classification),
        confidence=verdict.confidence,
        produced_by=verdict.produced_by,
        brand=verdict.brand,
        kit_family=verdict.kit_family,
        rationale=verdict.rationale,
    )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_router(
    db_path: str = DEFAULT_DB_PATH,
    artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
) -> APIRouter:
    """Costruisce il router con le dipendenze iniettate."""

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
            logger.error("Background analysis failed: %s", exc)

    # ──────────────────────────────────────────────────────────────────────
    # POST /analyses — submit a new analysis (202 Accepted)
    # ──────────────────────────────────────────────────────────────────────

    @router.post(
        "/analyses",
        status_code=202,
        response_model=AnalysisCreatedResponse,
    )
    async def create_analysis(payload: AnalysisCreateRequest, request: Request):
        """Avvia una nuova analisi in background.

        Il target viene creato e salvato come ``queued`` **prima** di
        lanciare ``asyncio.create_task`` — un GET immediato sull'id
        restituito non darà mai 404.
        """
        url = payload.url.strip()

        # Crea e salva il target come "queued" — AWAITED prima del task
        target = AnalysisTarget(input_url=url)
        await save_target(target, [], [], [], None, db_path=db_path)

        budget = None
        if payload.budget:
            budget = Budget(
                max_depth=payload.budget.max_depth,
                max_nodes=payload.budget.max_nodes,
                timeout_s=payload.budget.timeout_s,
            )

        # Avvia la pipeline in background (NON await — rispondiamo subito)
        # Browser condiviso dal lifespan dell'app (app.state.browser_pool):
        # nessun launch Chromium per richiesta.  Nei test con router
        # standalone (nessun lifespan eseguito) il getattr dà None e la
        # pipeline degrada al browser effimero — invariato.
        task = asyncio.create_task(
            run_full_analysis(
                url,
                budget=budget,
                classify=payload.classify,
                target=target,
                db_path=db_path,
                browser_pool=getattr(request.app.state, "browser_pool", None),
            )
        )
        task.add_done_callback(_on_task_done)

        logger.info("Analysis %s queued for %s", target.id, url)
        return AnalysisCreatedResponse(
            id=str(target.id),
            status="queued",
            input_url=url,
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses — elenco di tutte le sottomissioni (dashboard)
    # ──────────────────────────────────────────────────────────────────────

    @router.get("/analyses", response_model=AnalysisListResponse)
    async def list_analyses(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        status: Optional[str] = Query(default=None, description="Filtra per stato"),
        classification: Optional[str] = Query(
            default=None, description="Filtra per classificazione del verdetto"
        ),
        q: Optional[str] = Query(
            default=None, description="Ricerca su input_url/final_url"
        ),
    ):
        """Elenca le sottomissioni, più recenti prima — usato dalla dashboard
        di monitoraggio. Paginato; filtrabile per stato, classificazione e
        sottostringa dell'URL."""
        rows = await list_targets(
            limit=limit,
            offset=offset,
            status=status,
            classification=classification,
            search=q,
            db_path=db_path,
        )
        total = await count_targets(
            status=status,
            classification=classification,
            search=q,
            db_path=db_path,
        )
        return AnalysisListResponse(
            total=total,
            limit=limit,
            offset=offset,
            items=[AnalysisListEntry(**r) for r in rows],
        )

    # ──────────────────────────────────────────────────────────────────────
    # POST /analyses/delete — eliminazione definitiva (dashboard)
    # DEVE essere prima di /analyses/{target_id}: "delete" non va mai
    # catturato come target_id da una route parametrizzata.
    # ──────────────────────────────────────────────────────────────────────

    @router.post(
        "/analyses/delete",
        response_model=AnalysesDeleteResponse,
    )
    async def delete_analyses(payload: AnalysesDeleteRequest):
        """Elimina definitivamente una o più sottomissioni.

        Prima cancella le righe da SQLite (transazione unica — la cascata
        ripulisce state/transition/evidence/verdict), POI rimuove le
        cartelle artefatto dei soli ID eliminati con successo.  L'ordine
        è voluto: se la cancellazione DB fallisse, gli artefatti restano
        intatti.  Una lista ``ids`` vuota → 400: nessuna eliminazione
        silenziosa "di tutto per errore".
        """
        if not payload.ids:
            raise HTTPException(
                status_code=400,
                detail="La lista 'ids' è vuota: nessuna eliminazione eseguita",
            )

        result = await delete_targets(payload.ids, db_path=db_path)

        # Pulizia artefatti SOLO per gli ID eliminati con successo,
        # DOPO il commit di SQLite (mai prima).
        not_found = set(result["not_found"])
        deleted_ids = [tid for tid in dict.fromkeys(payload.ids) if tid not in not_found]
        if deleted_ids:
            remove_artifact_dirs(deleted_ids, artifact_root)

        return AnalysesDeleteResponse(
            deleted_count=result["deleted_count"],
            not_found=result["not_found"],
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses/history — DEVE essere prima di /analyses/{target_id}
    # altrimenti "history" viene catturato come target_id → 404
    # ──────────────────────────────────────────────────────────────────────

    @router.get(
        "/analyses/history",
        response_model=HistoryResponse,
    )
    async def get_history(
        url: Optional[str] = Query(default=None),
        url_hash: Optional[str] = Query(default=None),
    ):
        """Cerca analisi storiche per URL o url_hash.

        Fornisci **esattamente uno** tra ``url`` e ``url_hash``.
        Se fornisci un hash SHA-256 (64 hex), viene usato direttamente;
        altrimenti l'URL viene passato a ``ingest()`` per calcolare
        l'hash con la stessa logica usata al momento del salvataggio.
        """
        if (url is None) == (url_hash is None):
            raise HTTPException(
                status_code=422,
                detail="Fornisci esattamente uno tra 'url' e 'url_hash'",
            )

        resolved_hash: str
        if url_hash is not None:
            resolved_hash = url_hash.lower()
        elif _SHA256_RE.fullmatch(url):
            # È già un hash SHA-256 → usalo direttamente (regola di cli.py)
            resolved_hash = url.lower()
        else:
            from graph_engine.ingestion.pipeline import ingest

            resolved_hash = ingest(url)["url_hash"]

        rows = await get_history_for_url_hash(resolved_hash, db_path=db_path)
        history = [HistoryEntry(**dict(r)) for r in rows]

        return HistoryResponse(
            url=url,
            url_hash=resolved_hash,
            history=history,
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses/{target_id} — summary (senza grafo completo)
    # ──────────────────────────────────────────────────────────────────────

    @router.get(
        "/analyses/{target_id}",
        response_model=AnalysisSummaryResponse,
    )
    async def get_analysis_summary(target_id: str):
        """Restituisce lo stato corrente di un'analisi (target + verdict + conteggi).

        Non include il grafo completo — per quello usa ``/analyses/{id}/graph``.
        """
        data = await get_target_by_id(target_id, db_path=db_path)
        if data is None:
            raise HTTPException(status_code=404, detail="Analisi non trovata")

        return AnalysisSummaryResponse(
            target=_to_target_summary(data["target"]),
            verdict=_to_verdict_summary(data.get("verdict")),
            num_states=len(data.get("states", [])),
            num_transitions=len(data.get("transitions", [])),
            num_evidence=len(data.get("evidence", [])),
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses/{target_id}/graph — grafo completo
    # ──────────────────────────────────────────────────────────────────────

    @router.get(
        "/analyses/{target_id}/graph",
        response_model=AnalysisGraphResponse,
    )
    async def get_analysis_graph(target_id: str):
        """Restituisce il grafo completo: target, states, transitions, evidence, verdict."""
        data = await get_target_by_id(target_id, db_path=db_path)
        if data is None:
            raise HTTPException(status_code=404, detail="Analisi non trovata")

        return AnalysisGraphResponse(
            target=_to_target_summary(data["target"]),
            states=[s.model_dump(mode="json") for s in data.get("states", [])],
            transitions=[
                t.model_dump(mode="json") for t in data.get("transitions", [])
            ],
            evidence=[
                e.model_dump(mode="json") for e in data.get("evidence", [])
            ],
            verdict=_to_verdict_summary(data.get("verdict")),
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses/{target_id}/artifacts — listing ricorsivo
    # ──────────────────────────────────────────────────────────────────────

    @router.get(
        "/analyses/{target_id}/artifacts",
        response_model=ArtifactListing,
    )
    async def get_artifacts(target_id: str):
        """Elenca i file artefatto (screenshot, DOM, HAR) per un'analisi."""
        # Verifica che il target esista
        if await get_target_by_id(target_id, db_path=db_path) is None:
            raise HTTPException(status_code=404, detail="Analisi non trovata")

        root = artifact_root / target_id
        files: list[ArtifactFile] = []
        if root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    files.append(
                        ArtifactFile(
                            path=str(path.relative_to(root)),
                            name=path.name,
                            size_bytes=path.stat().st_size,
                        )
                    )

        return ArtifactListing(
            target_id=target_id,
            count=len(files),
            files=files,
        )

    # ──────────────────────────────────────────────────────────────────────
    # GET /analyses/{target_id}/artifacts/{state_id}/{filename} — contenuto
    # ──────────────────────────────────────────────────────────────────────

    @router.get("/analyses/{target_id}/artifacts/{state_id}/{filename}")
    async def get_artifact_file(target_id: str, state_id: str, filename: str):
        """Serve il contenuto grezzo di un singolo artefatto (screenshot,
        DOM, HAR) — usato dalla dashboard per mostrare gli screenshot.

        ``filename`` è vincolato a un whitelist fisso (i tre soli file che
        ``_save_artifacts`` scrive). Combinato col fatto che FastAPI non fa
        passare '/' in un segmento di path senza il convertitore ``:path``,
        questo esclude path traversal per costruzione — non serve
        risolvere/validare il path manualmente.
        """
        media_type = _ARTIFACT_MEDIA_TYPES.get(filename)
        if media_type is None:
            raise HTTPException(status_code=404, detail="Artefatto non trovato")

        if await get_target_by_id(target_id, db_path=db_path) is None:
            raise HTTPException(status_code=404, detail="Analisi non trovata")

        file_path = artifact_root / target_id / state_id / filename
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail="Artefatto non trovato")

        return FileResponse(file_path, media_type=media_type)

    # ──────────────────────────────────────────────────────────────────────
    # GET /health
    # ──────────────────────────────────────────────────────────────────────

    @router.get("/health", response_model=HealthResponse)
    async def health():
        """Health check — conta i job in esecuzione."""
        ensure_data_dir(db_path)
        async with aiosqlite.connect(db_path) as conn:
            await conn.executescript(DDL)
            async with conn.execute(
                "SELECT COUNT(*) FROM analysis_target WHERE status = 'running'"
            ) as cur:
                row = await cur.fetchone()

        running = row[0] if row else 0
        return HealthResponse(status="ok", running_jobs=running)

    return router
