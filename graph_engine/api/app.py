"""FastAPI application for IVX-GraphEngine.

Avvio::

    uvicorn graph_engine.api.app:app --reload

Oppure programmatico::

    from graph_engine.api.app import create_app
    app = create_app(db_path="data/custom.db")
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from graph_engine.api.pipeline_runner import DEFAULT_ARTIFACT_ROOT
from graph_engine.api.routes import build_router
from graph_engine.storage.schema import DEFAULT_DB_PATH


def create_app(
    db_path: str = DEFAULT_DB_PATH,
    artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
) -> FastAPI:
    """Costruisce l'app FastAPI con dipendenze iniettabili (per test)."""
    app = FastAPI(
        title="IVX GraphEngine API",
        version="0.1.0",
        description=(
            "Interfaccia HTTP asincrona per la pipeline L0→L5 di analisi "
            "di URL di phishing. Job asincroni con stato persistito su "
            "SQLite — nessuna coda esterna."
        ),
    )
    app.include_router(
        build_router(db_path=db_path, artifact_root=artifact_root)
    )
    return app


# Istanza predefinita per uvicorn
app = create_app()
