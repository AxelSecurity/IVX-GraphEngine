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
| **L2 — OSINT passivo** | Interroga fonti esterne senza toccare il sito: certificati SSL (ctlogs.dev), whois (RDAP), DNS, feed di minacce note (URLhaus, opzionali MISP/OpenCTI). Trova anche "domini fratelli" della stessa campagna |
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
FastAPI dell'API (nessun servizio separato, nessuna porta aggiuntiva):
con l'API già avviata, apri `http://localhost:8000/dashboard`.

Dalla voce **"Liste forzate"** si gestiscono whitelist/blacklist per
**domini** (match sul dominio registrabile, eTLD+1) e per **URL** (match
sulla URL normalizzata senza query/frammento). Un hit forza subito il
verdetto e salta l'analisi — sia nella dashboard che nella risposta a
Trellix; in caso di conflitto vince il match più specifico (URL > dominio).

I dettagli di ogni livello, gli schemi dati e le decisioni tecniche sono
documentati in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Con Docker (deployment single-node)

Il servizio gira in un container con `docker-compose.yml` — un solo
servizio, coerentemente con la decisione presa all'inizio del progetto
(single-node su SQLite, non orchestrato). Lo stesso container serve sia
l'API che la dashboard (`/dashboard`), sulla stessa porta.

```bash
# 1. Copia la configurazione accanto a docker-compose.yml
#    (radice del progetto, NON dentro data/):
cp .env.example .env   # poi valorizza le variabili che ti servono

# 2. Build dell'immagine (installa anche chromium Playwright
#    e le sue librerie di sistema nello stesso layer)
docker compose build

# 3. Avvio in background
docker compose up -d

# 4. Verifica che sia in salute
curl http://localhost:8000/health

# 5. Log in tempo reale
docker compose logs -f

# 6. Arresto
docker compose down   # i dati restano nel volume ./data
```

Note operative:
- **Porta configurabile**: `HOST_PORT=8080 docker compose up -d` (default 8000)
- **Persistenza**: tutto ciò che è prezioso (DB SQLite `graph_engine.db`,
  artefatti di esplorazione, cache OSINT) vive in `./data`, montato come
  volume in `/app/data` — sopravvive a riavvii e ricreazioni del container
- **Utente non-root**: il server non gira mai come root nel container
- **Un solo worker uvicorn**: SQLite ha un solo scrittore; per più
  throughput la strada è l'async dentro il singolo processo

### Le due viste sullo stesso dato

L'API espone due endpoint che rispondono sulla **stessa analisi** (stesso
target, stesso grafo, stesso verdetto in SQLite) — non sono due sistemi
separati:

| Endpoint | Uso |
|---|---|
| `GET /trellix/analyze?url=...` | Risposta **sincrona** compatibile con Trellix IVX (verdetto `safe`/`malicious` entro ~48s; se l'analisi sfora, risponde onestamente `Analysis-Incomplete` e continua in background) |
| `POST /analyses` + `GET /analyses/{id}` | Avvio asincrono (202 Accepted) e stato dell'analisi |
| `GET /analyses/{id}/graph` | **Il JSON completo**: target, tutti gli stati del grafo, le transizioni, le evidenze di ogni livello e il verdetto |

Il JSON mostrato dal CLI (`python -m graph_engine.cli <url>`) è lo stesso
contenuto di `GET /analyses/{id}/graph`.

#### Contratto di `GET /trellix/analyze`

Trellix chiama il modulo **passando l'URL in query string** e **attendendo
che la risposta contenga il JSON** del verdetto — non c'è un secondo passo
asincrono:

```bash
curl -G http://localhost:8000/trellix/analyze \
     --data-urlencode "url=https://example.org/"
```

Risposta (200, `Content-Type: application/json`) — verdetto binario:

```json
{
  "verdict": "safe",
  "confidence": 0.95,
  "signature": "No Threats Detected",
  "recommended_action": "allow",
  "reason": "Analisi completata — nessun indicatore di phishing rilevato."
}
```

Campi:

| Campo | Valori | Significato |
|---|---|---|
| `verdict` | `safe` \| `malicious` | Il verdetto binario atteso da Trellix |
| `confidence` | 0.0–1.0 | Fiducia del verdetto (safe: ≥0.9 se completo, 0.1 se incompleto; malicious: ≥0.8) |
| `signature` | testo breve | Firma leggibile; su `safe` è sempre benigna (`No Threats Detected` o simile), mai "Phishing: …" |
| `recommended_action` | `allow` \| `block` | Azione raccomandata a Trellix |
| `reason` | testo | Motivazione leggibile (il `rationale` del classificatore, se presente) |

Il chiamante resta in attesa fino a ~48s (deadline 60s di Frontdoor). Se
l'analisi non è terminata entro la finestra, la risposta arriva comunque ma
lo dichiara onestamente — `"verdict": "safe"`, `"confidence": 0.1`,
`"signature": "Analysis-Incomplete — Benign By Default"` — e l'analisi
continua in background: il risultato completo resta disponibile su
`GET /analyses/{id}` (l'`id` è la stessa risorsa usata dal flusso
asincrono POST).

## Test

```bash
pytest                # suite predefinita (nessuna chiamata di rete reale)
pytest -m integration # test con rete reale (httpbin.org)
```
