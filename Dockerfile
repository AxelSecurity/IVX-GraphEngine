# syntax=docker/dockerfile:1

FROM python:3.11-slim

# --- Dipendenze di sistema ---------------------------------------------------
# Verifica su requirements.txt: TUTTE le dipendenze distribuiscono wheel
# precompilate per linux (x86_64 e arm64) — pydantic-core (Rust), lxml,
# mmh3, uvloop/httptools (uvicorn[standard]), yarl/multidict/frozenlist
# (aiohttp), cryptography (azure-identity).  Nessuna estensione viene
# compilata a build time → build-essential NON serve.
# curl serve SOLO per l'healthcheck di docker-compose: python:3.11-slim
# non include né curl né wget.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# --- Ambiente Python ---------------------------------------------------------
# venv esplicito: le immagini slim basate su Debian bookworm applicano
# PEP 668 (pip install a livello di sistema è rifiutato).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # I browser Playwright finiscono fuori da $HOME (root in build, poi
    # utente non-root a runtime: /root/.cache non sarebbe leggibile).
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# --- Dipendenze Python -------------------------------------------------------
COPY requirements.txt .
RUN pip install -r requirements.txt

# --- Browser Playwright -------------------------------------------------------
# UNICO comando: browser chromium e librerie di sistema native nello
# stesso layer di build → sempre coerenti tra loro (niente
# disallineamento versione browser/librerie, già visto su Ubuntu).
RUN playwright install --with-deps chromium

# --- Codice applicativo ------------------------------------------------------
COPY graph_engine ./graph_engine

# --- Utente non-root ---------------------------------------------------------
# Il server non gira mai come root: l'utente ha un UID fisso e possiede
# sia il codice sia i browser (sola lettura a runtime).
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /ms-playwright /app
USER appuser

EXPOSE 8000

# UN solo worker: SQLite ha un solo scrittore — più processi
# significherebbe connessioni separate in contesa di scrittura.  Per più
# throughput la strada è l'async dentro il singolo processo, non più
# processi su SQLite.
CMD ["uvicorn", "graph_engine.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
