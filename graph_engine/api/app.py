"""FastAPI application for IVX-GraphEngine.

Avvio::

    uvicorn graph_engine.api.app:app --reload

Oppure programmatico::

    from graph_engine.api.app import create_app
    app = create_app(db_path="data/custom.db")
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from graph_engine.api.browser_pool import BrowserPool
from graph_engine.api.pipeline_runner import DEFAULT_ARTIFACT_ROOT
from graph_engine.api.routes import build_router
from graph_engine.api.routes_trellix import build_trellix_router
from graph_engine.storage.schema import DEFAULT_DB_PATH

# [TIMING] diagnostica temporanea: uvicorn configura solo i propri
# logger ("uvicorn.*") e il root resta senza handler — senza questa
# riga NESSUN log applicativo (graph_engine.*) esce dal container.
# Da rivalutare come configurazione stabile (level dal settings).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def _make_lifespan(enable_browser_pool: bool):
    """Costruisce il lifespan di FastAPI.

    Con il pool attivo, UN solo processo Chromium viene lanciato
    all'avvio dell'applicazione e riusato da tutte le analisi
    (context freschi per richiesta — isolamento cookie/storage), e
    chiuso ordinatamente allo shutdown.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not enable_browser_pool:
            yield
            return

        pool = BrowserPool()
        await pool.start()
        app.state.browser_pool = pool
        logger = logging.getLogger("graph_engine.api.app")
        logger.info("Browser condiviso pronto per le richieste")
        try:
            yield
        finally:
            await pool.stop()
            logger.info("Browser condiviso chiuso")

    return lifespan


def create_app(
    db_path: str = DEFAULT_DB_PATH,
    artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
    enable_browser_pool: bool = True,
) -> FastAPI:
    """Costruisce l'app FastAPI con dipendenze iniettabili (per test).

    Args:
        db_path: Percorso del database SQLite.
        artifact_root: Directory radice per gli artefatti (screenshot,
                       DOM, HAR).
        enable_browser_pool: Se ``True`` (default), il lifespan avvia il
                             browser Chromium condiviso (``app.state.
                             browser_pool``).  Nei test l'ASGITransport
                             non esegue il lifespan; il flag resta
                             disponibile per disattivarlo esplicitamente.
    """
    app = FastAPI(
        title="IVX GraphEngine API",
        version="0.1.0",
        description=(
            "Interfaccia HTTP asincrona per la pipeline L0→L5 di analisi "
            "di URL di phishing. Job asincroni con stato persistito su "
            "SQLite — nessuna coda esterna."
        ),
        lifespan=_make_lifespan(enable_browser_pool),
    )
    app.include_router(
        build_router(db_path=db_path, artifact_root=artifact_root)
    )
    app.include_router(
        build_trellix_router(db_path=db_path)
    )
    return app


# Istanza predefinita per uvicorn
app = create_app()
