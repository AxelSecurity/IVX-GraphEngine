"""FastAPI application for GraphEngine.

Avvio::

    uvicorn graph_engine.api.app:app --reload

Oppure programmatico::

    from graph_engine.api.app import create_app
    app = create_app(db_path="data/custom.db")
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from graph_engine.api import auth
from graph_engine.api.auth_routes import build_auth_router
from graph_engine.api.browser_pool import BrowserPool
from graph_engine.api.jobs import AnalysisJobs
from graph_engine.api.retention import retention_loop
from graph_engine.api.pipeline_runner import DEFAULT_ARTIFACT_ROOT
from graph_engine.api.routes import build_router
from graph_engine.api.routes_external import build_external_router
from graph_engine.config import settings
from graph_engine.storage.schema import DEFAULT_DB_PATH

# Dashboard statica (HTML/CSS/JS puri, nessuna build): consuma le stesse
# API REST sotto /analyses. Montata a parte da /dashboard, mai sulla radice
# "/", cosi le route API restano indipendenti dall'ordine di registrazione.
_DASHBOARD_DIR = Path(__file__).parent / "static" / "dashboard"

class _HealthCheckAccessFilter(logging.Filter):
    """Scarta dal log di accesso di uvicorn i ``GET /health`` riusciti.

    Il healthcheck di Docker li chiama ogni 30s (~2900 righe al giorno)
    e coprivano tutto il resto; un /health fallito resta registrato.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 5:
            path, status = args[2], args[4]
            if str(path).split("?", 1)[0] == "/health" and str(status) == "200":
                return False
        return True


def configure_logging(level_name: str | None = None) -> int:
    """Configura i log del processo e restituisce il livello applicato.

    - uvicorn configura solo i propri logger ("uvicorn.*") e lascia il
      root senza handler: senza ``basicConfig`` nessun log applicativo
      (graph_engine.*) uscirebbe dal container;
    - livello da ``LOG_LEVEL`` (default INFO; valori ignoti → INFO);
    - librerie Azure almeno a WARNING: a INFO la HttpLoggingPolicy
      scriveva ogni richiesta Foundry/Vision con tutte le intestazioni
      (oltre la metà delle righe di log);
    - i /health riusciti escono dal log di accesso.
    """
    name = (level_name or settings.log_level or "INFO").strip().upper()
    level = logging.getLevelName(name)
    if not isinstance(level, int):
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(level)
    logging.getLogger("azure").setLevel(max(level, logging.WARNING))
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _HealthCheckAccessFilter) for f in access.filters):
        access.addFilter(_HealthCheckAccessFilter())
    return level


configure_logging()

# Path esenti dal middleware di sessione (decisione utente 2026-09-01:
# il login protegge UI + tutte le API, tranne queste):
#   - /health             probe di Front Door / container
#   - /auth/login|logout  il login va raggiunto anonimo, il logout deve
#                         sempre ripulire il cookie
#   - /api/v1             API esterna, protetta dalla propria API key
#                         (X-API-Key)
#   - /dashboard          codice statico della SPA: è il frontend che
#                         mostra il form di login quando /auth/me dà 401
_EXEMPT_PREFIXES = ("/health", "/auth/login", "/auth/logout", "/api/v1", "/dashboard")

# Utente sintetico esposto in ``request.state.user`` per le richieste
# autenticate con API key invece che con la sessione.
_API_KEY_USER = {"username": "api-key", "role": "api"}


def _is_exempt(path: str) -> bool:
    """True se il path non richiede sessione (vedi ``_EXEMPT_PREFIXES``)."""
    if path == "/":
        return True  # la radice reindirizza solo alla dashboard
    for prefix in _EXEMPT_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _api_key_allowed(method: str, path: str) -> bool:
    """True se la route accetta la API key in alternativa alla sessione.

    Solo il ciclo di vita di un'analisi, per i client machine-to-machine:
    sottomissione (``POST /analyses``) e lettura/polling (``GET
    /analyses`` e sotto-risorse).  Cancellazioni, liste forzate e
    gestione utenti restano riservate alla sessione della dashboard.
    """
    if path == "/analyses":
        return method in ("GET", "POST")
    return method == "GET" and path.startswith("/analyses/")


def _make_lifespan(enable_browser_pool: bool, artifact_root: Path):
    """Costruisce il lifespan di FastAPI.

    All'avvio crea (se serve) l'amministratore bootstrap della
    dashboard.  Con il pool attivo, UN solo processo Chromium viene
    lanciato all'avvio dell'applicazione e riusato da tutte le analisi
    (context freschi per richiesta — isolamento cookie/storage), e
    chiuso ordinatamente allo shutdown.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger = logging.getLogger("graph_engine.api.app")
        await auth.ensure_bootstrap_admin(app.state.db_path)
        logger.info("Autenticazione pronta (admin bootstrap garantito)")

        # Retention: cancella periodicamente artefatti e cache OSINT
        # vecchi (graph_engine.api.retention) — il DB non viene toccato.
        from graph_engine.osint.cache import _CACHE_ROOT

        retention_task = asyncio.create_task(
            retention_loop(artifact_root, _CACHE_ROOT)
        )

        pool = None
        if enable_browser_pool:
            pool = BrowserPool()
            await pool.start()
            app.state.browser_pool = pool
            logger.info("Browser condiviso pronto per le richieste")
        try:
            yield
        finally:
            retention_task.cancel()
            if pool is not None:
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
        title="GraphEngine API",
        version="0.1.0",
        description=(
            "Interfaccia HTTP asincrona per la pipeline L0→L5 di analisi "
            "di URL di phishing. Job asincroni con stato persistito su "
            "SQLite — nessuna coda esterna."
        ),
        lifespan=_make_lifespan(enable_browser_pool, artifact_root),
    )
    # Riferimento per lifespan e test: il middleware di sessione non
    # accede al DB (sessioni in memoria), le route /auth sì.
    app.state.db_path = db_path
    # Registro dei job: limite di concorrenza, dedup in-flight e
    # riferimenti forti ai task di analisi (vedi graph_engine.api.jobs).
    app.state.jobs = AnalysisJobs()

    # Middleware di sessione: protegge TUTTO tranne health, login/logout,
    # l'API esterna (API key propria) e il codice statico della
    # dashboard.  Sulle route del ciclo di vita delle analisi la API key
    # vale in alternativa al cookie (client machine-to-machine).  Chi è
    # autenticato viene esposto alle route in ``request.state.user``.
    @app.middleware("http")
    async def _session_auth_middleware(request: Request, call_next):
        path = request.url.path
        if _is_exempt(path):
            return await call_next(request)
        session = auth.get_session(auth.read_session_cookie(request))
        if session is None and _api_key_allowed(request.method, path):
            if auth.api_key_valid(request):
                session = _API_KEY_USER
        if session is None:
            return JSONResponse(
                {"detail": "Autenticazione richiesta"},
                status_code=401,
            )
        request.state.user = session
        return await call_next(request)

    app.include_router(
        build_router(db_path=db_path, artifact_root=artifact_root)
    )
    app.include_router(
        build_external_router(db_path=db_path)
    )
    app.include_router(
        build_auth_router(db_path=db_path)
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
