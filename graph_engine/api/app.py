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
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from graph_engine.api.pipeline_runner import DEFAULT_ARTIFACT_ROOT
from graph_engine.api.routes import build_router
from graph_engine.api.routes_trellix import build_trellix_router
from graph_engine.storage.schema import DEFAULT_DB_PATH

# Dashboard statica (HTML/CSS/JS puri, nessuna build): consuma le stesse
# API REST sotto /analyses. Montata a parte da /dashboard, mai sulla radice
# "/", cosi le route API restano indipendenti dall'ordine di registrazione.
_DASHBOARD_DIR = Path(__file__).parent / "static" / "dashboard"


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
    app.include_router(
        build_trellix_router(db_path=db_path)
    )

    @app.get("/", include_in_schema=False)
    async def _root():
        return RedirectResponse(url="/dashboard/")

    if _DASHBOARD_DIR.is_dir():
        app.mount(
            "/dashboard",
            StaticFiles(directory=_DASHBOARD_DIR, html=True),
            name="dashboard",
        )

    return app


# Istanza predefinita per uvicorn
app = create_app()
