# IVX-GraphEngine — immagine unica per API + dashboard di monitoraggio.
#
# La dashboard (graph_engine/api/static/dashboard/) è servita dalla stessa
# app FastAPI dell'API — nessun container/servizio separato: costruire e
# avviare questa immagine avvia entrambe.

FROM python:3.11-slim

# ca-certificates: richiesto dalle chiamate HTTPS in uscita (L2 OSINT, L5
# Foundry/Vision). Il resto delle dipendenze di sistema di Chromium viene
# installato da "playwright install --with-deps" più sotto, così restano
# sempre allineate alla versione di playwright fissata in requirements.txt
# invece che a un tag di immagine Playwright pinnato a mano.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

COPY . .

# data/ ospita il DB SQLite, gli artefatti (screenshot/DOM/HAR) e la cache
# OSINT — va montato come volume per persistere tra un riavvio e l'altro.
VOLUME ["/app/data"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "graph_engine.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
