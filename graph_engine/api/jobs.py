"""Registro in-process dei job di analisi.

Un solo processo uvicorn (SQLite single-writer, Chromium condiviso):
questo registro è il punto unico da cui le route avviano le pipeline.
Garantisce tre cose che un ``asyncio.create_task`` nudo non dà:

1. **Riferimento forte** ai task in corso — l'event loop tiene solo
   riferimenti deboli: un task "fire-and-forget" non referenziato può
   essere raccolto dal GC a metà esecuzione.
2. **Limite di concorrenza** (``MAX_CONCURRENT_ANALYSES``): le pipeline
   oltre il limite attendono uno slot restando ``queued`` su SQLite.
3. **Dedup delle analisi in corso** per ``url_hash``: una seconda
   richiesta sincrona per lo stesso URL si aggancia al task già in
   esecuzione invece di lanciarne un'altra.

I task sono indipendenti dalla richiesta HTTP che li ha avviati: chi li
attende deve usare ``asyncio.shield`` (vedi ``routes_external``), così
una disconnessione del client non cancella l'analisi.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from graph_engine.api.pipeline_runner import run_full_analysis
from graph_engine.config import settings
from graph_engine.models import AnalysisTarget
from graph_engine.storage.repository import save_target
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.jobs")


class AnalysisJobs:
    """Avvio, tracciamento e dedup delle pipeline di analisi."""

    def __init__(self, max_concurrent: Optional[int] = None) -> None:
        limit = (
            max_concurrent
            if max_concurrent is not None
            else settings.max_concurrent_analyses
        )
        self._max_concurrent = max(1, int(limit))
        # Creato al primo avvio, dentro l'event loop in esecuzione.
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._tasks: set[asyncio.Task] = set()
        self._inflight: dict[str, tuple[str, asyncio.Task]] = {}

    @property
    def running_count(self) -> int:
        """Numero di task di analisi non ancora terminati."""
        return sum(1 for t in self._tasks if not t.done())

    def inflight(self, url_hash: str) -> Optional[tuple[str, asyncio.Task]]:
        """``(target_id, task)`` dell'analisi in corso per *url_hash*."""
        entry = self._inflight.get(url_hash)
        if entry is None or entry[1].done():
            return None
        return entry

    def start(
        self,
        raw_url: str,
        target: AnalysisTarget,
        *,
        url_hash: Optional[str] = None,
        save_queued: bool = False,
        **run_kwargs: Any,
    ) -> asyncio.Task:
        """Avvia la pipeline per *target* e restituisce il task.

        Metodo SINCRONO: tra un ``inflight()`` che restituisce ``None`` e
        la registrazione fatta qui non c'è alcun ``await``, quindi due
        richieste concorrenti non possono avviare due analisi dello
        stesso URL.

        Args:
            raw_url: URL da analizzare (input della pipeline).
            target: Target dell'analisi.
            url_hash: Se passato, il task viene registrato per la dedup
                (``inflight``) fino al suo completamento.
            save_queued: Se True, il task persiste il target come
                ``queued`` prima di attendere lo slot (il chiamante non
                deve fare ``await`` prima di registrare il job).  Se
                False, il chiamante lo ha già salvato.
            **run_kwargs: Inoltrati a ``run_full_analysis``.
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)
        semaphore = self._semaphore

        async def _run() -> str:
            if save_queued:
                await save_target(
                    target, [], [], [], None,
                    db_path=run_kwargs.get("db_path", DEFAULT_DB_PATH),
                )
            async with semaphore:
                return await run_full_analysis(
                    raw_url, target=target, **run_kwargs
                )

        task = asyncio.create_task(_run(), name=f"analysis-{target.id}")
        self._tasks.add(task)
        if url_hash:
            self._inflight[url_hash] = (str(target.id), task)

        def _done(t: asyncio.Task) -> None:
            self._tasks.discard(t)
            if url_hash and self._inflight.get(url_hash, (None, None))[1] is t:
                del self._inflight[url_hash]
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                # Lo stato 'error' è già stato persistito dal runner.
                logger.error("Analysis %s failed: %s", target.id, exc)

        task.add_done_callback(_done)
        return task


def get_jobs(app) -> AnalysisJobs:
    """Il registro dei job dell'app (creato al primo uso)."""
    jobs = getattr(app.state, "jobs", None)
    if jobs is None:
        jobs = AnalysisJobs()
        app.state.jobs = jobs
    return jobs
