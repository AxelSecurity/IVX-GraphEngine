# IVX-GraphEngine

Uno strumento che prende in input un URL sospetto (es. segnalato come possibile
phishing) e lo analizza in automatico, seguendolo passo passo — redirect,
pagine intermedie, eventuali click — fino ad arrivare alla pagina finale.
Il risultato è un **grafo**: ogni pagina incontrata è un nodo, ogni redirect
o azione è un collegamento tra due nodi. Alla fine lo strumento dice se il
sito è probabilmente benigno, sospetto o phishing, e perché.

È un componente indipendente della toolchain Horus/IntelIVX: si collega agli
altri sistemi via HTTP, non viene mai importato direttamente nel loro codice.

## Come funziona, in breve

L'analisi è divisa in livelli (L0-L5), ciascuno con un compito preciso.
Ogni livello produce **evidenze** (segnali osservati, con un peso di rischio)
che si accumulano fino al verdetto finale:

| Livello | Cosa fa |
|---|---|
| **L0 — Ingestion** | Pulisce l'URL in ingresso: rimuove wrapper di sicurezza (es. link riscritti da gateway email), decodifica, normalizza |
| **L1 — Lessicale** | Analizza l'URL come testo: somiglianza con domini noti (typosquatting), entropia sospetta, pattern di infrastruttura tipici del phishing |
| **L2 — OSINT passivo** | Interroga fonti esterne senza toccare il sito: certificati SSL (crt.sh), whois (RDAP), DNS, feed di minacce note (URLhaus, opzionali MISP/OpenCTI). Trova anche "domini fratelli" della stessa campagna |
| **L3 — Attivo a bassa intensità** | Richieste HTTP mirate (catena di redirect, favicon, impronta TLS "JARM", confronto risposte con User-Agent diversi per scoprire cloaking) — mai esecuzione di JavaScript |
| **L4 — Esplorazione del grafo** | Apre un vero browser (Playwright) e naviga il sito seguendo redirect e cliccando sugli elementi più plausibili (bottoni "continua", gate CAPTCHA), costruendo il grafo di stati fino al payload finale |
| **L5 — Classificazione** | Un filtro deterministico intercetta i casi banali; per il resto un modello AI (Azure Foundry) valuta tutte le evidenze raccolte e produce il verdetto finale con motivazione |

Il risultato di ogni analisi viene salvato in modo permanente (SQLite):
ogni run è una nuova riga, non si sovrascrive mai nulla, così si può
consultare lo storico di un URL già visto in passato.

## Cosa NON fa (scelte deliberate)

- **Non inserisce mai dati nei form.** Il progetto osserva e classifica,
  non compila né invia credenziali, nemmeno finte ("canary").
- **Non risolve CAPTCHA reali.** Al massimo aspetta un'auto-risoluzione o
  clicca una checkbox semplice.
- **Ogni classificazione AI parte "pulita".** Nessuna memoria tra
  un'analisi e l'altra: evita che il contesto di un caso precedente
  influenzi (falsando) il giudizio su un sito nuovo.

## Come usarlo

```bash
# Setup iniziale
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# Analisi da riga di comando
python -m graph_engine.cli <url>
python -m graph_engine.cli <url> --classify        # con classificazione L5 (AI)
python -m graph_engine.cli <url> --history <url>   # solo storico, nessuna nuova analisi

# Come servizio HTTP (per integrazioni, es. con IntelIVX/Trellix)
uvicorn graph_engine.api.app:app --reload
```

## Dashboard di monitoraggio

Una dashboard web mostra tutte le sottomissioni effettuate e, cliccandoci
sopra, tutti i dettagli estratti — grafo di esplorazione, stati con
screenshot, evidenze per livello, verdetto. È servita dalla stessa app
FastAPI dell'API (nessun servizio separato): con l'API già avviata,
apri `http://localhost:8000/dashboard`.

## Docker

```bash
docker compose up --build
```

Avvia in un solo container API + dashboard su `http://localhost:8000`
(dashboard su `/dashboard`). I dati (`data/`: DB SQLite, screenshot/DOM/HAR,
cache OSINT) sono montati come volume e sopravvivono ai riavvii. Per
abilitare `--classify` (Foundry) o l'arricchimento Vision, copia
`.env.example` in `.env`, valorizzalo e decommenta `env_file` in
`docker-compose.yml`.

I dettagli di ogni livello, gli schemi dati e le decisioni tecniche sono
documentati in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Test

```bash
pytest                # suite predefinita (nessuna chiamata di rete reale)
pytest -m integration # test con rete reale (httpbin.org)
```
