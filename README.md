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
screenshot, evidenze per livello, verdetto. In cima alla vista c'è anche
il form per **sottomettere nuovi URL** (classificazione L5 e budget
opzionali), con le stesse regole della POST `/analyses`. È servita dalla
stessa app FastAPI dell'API (nessun servizio separato, nessuna porta
aggiuntiva): con l'API già avviata, apri `http://localhost:8000/dashboard`.

Dalla voce **"Whitelist/Blacklist"** si gestiscono le liste forzate per
**domini** (match sul dominio registrabile, eTLD+1) e per **URL** (match
sulla URL normalizzata senza query/frammento). Un hit forza subito il
verdetto e salta l'analisi — sia nella dashboard che nella risposta a
Trellix; in caso di conflitto vince il match più specifico (URL > dominio).

Dalla voce **"Utenti"** (visibile solo agli amministratori) si gestiscono
gli account della dashboard: creazione, cambio ruolo
(`admin`/`operator`), cambio password ed eliminazione. Protezioni: non si
può eliminare il proprio account né eliminare o degradare a `operator`
l'ultimo amministratore rimasto; cambiare password o ruolo revoca le
sessioni attive dell'utente (comprese le proprie).

### Login e utenti

La dashboard **richiede il login**: le credenziali sono multi-utente in
SQLite (ruoli `admin`/`operator`, password con hash PBKDF2) e la sessione
vive in un cookie HttpOnly di 12h. Il login protegge anche **tutte le API
REST** (tranne `/health` e la route Trellix, che ha la sua API key): un
401 riporta alla schermata di accesso.

Al primo avvio viene creato l'admin bootstrap: credenziali da
`DASHBOARD_ADMIN_USER`/`DASHBOARD_ADMIN_PASSWORD` se valorizzate nel
`.env`, altrimenti utente `admin` con password casuale **stampata nel
log** (`docker compose logs`). Nota: il bootstrap parte solo a tabella
utenti **vuota** — cambiare le variabili del `.env` non sovrascrive
l'admin già esistente.

La gestione ordinaria avviene dalla dashboard (voce "Utenti", solo
admin); da CLI resta disponibile per l'emergenza (es. password
dimenticata):

```bash
docker compose exec graph-engine python -m graph_engine.api.auth_cli list
docker compose exec graph-engine python -m graph_engine.api.auth_cli add operatore --role operator
docker compose exec graph-engine python -m graph_engine.api.auth_cli passwd admin
```

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
- **Browser Chromium condiviso**: il lifespan dell'app mantiene un pool
  di browser Playwright riusati tra le richieste — nessun launch di
  Chromium per singola analisi
- **Autenticazione**: dashboard e API REST richiedono il login (utenti in
  SQLite, admin bootstrap al primo avvio — credenziali nel log se non
  valorizzate nel `.env`); la route Trellix richiede `X-API-Key`
  (`TRELLIX_API_KEY` nel `.env`, 503 se assente). Solo `/health` è aperto
  (probe del container)

### Le due viste sullo stesso dato

L'API espone due endpoint che rispondono sulla **stessa analisi** (stesso
target, stesso grafo, stesso verdetto in SQLite) — non sono due sistemi
separati:

| Endpoint | Uso |
|---|---|
| `GET /trellix/analyze?url=...` | Risposta **sincrona** compatibile con Trellix IVX: attende il completamento reale dell'analisi e porta sempre il verdetto finale (nessuna deadline imposta dal modulo — l'unica finestra è quella gestita a monte da Front Door/Trellix) |
| `POST /analyses` + `GET /analyses/{id}` | Avvio asincrono (202 Accepted) e stato dell'analisi |
| `GET /analyses/{id}/graph` | **Il JSON completo**: target, tutti gli stati del grafo, le transizioni, le evidenze di ogni livello e il verdetto |

Il JSON mostrato dal CLI (`python -m graph_engine.cli <url>`) è lo stesso
contenuto di `GET /analyses/{id}/graph`.

#### Contratto di `GET /trellix/analyze`

Trellix chiama il modulo **passando l'URL in query string** e **attendendo
che la risposta contenga il JSON** del verdetto — non c'è un secondo passo
asincrono. La route è **protetta da API key**: ogni richiesta deve portare
`X-API-Key` con il valore di `TRELLIX_API_KEY` (se la variabile non è
configurata la route risponde **503** — configurazione mancante, mai
aperta; il vecchio Bearer `TRELLIX_API_TOKEN` resta accettato per
retrocompatibilità):

```bash
curl -G http://localhost:8000/trellix/analyze \
     -H "X-API-Key: $TRELLIX_API_KEY" \
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
| `confidence` | 0.0–1.0 | Fiducia del verdetto (≥0.8-0.9 con verdetto definitivo; 0.1 sui rami non conclusivi: analisi in corso, fallita o senza classificazione) |
| `signature` | testo breve | Firma leggibile; su `safe` è sempre benigna (`No Threats Detected` o simile), mai "Phishing: …" |
| `recommended_action` | `allow` \| `block` | Azione raccomandata a Trellix |
| `reason` | testo | Motivazione leggibile (il `rationale` del classificatore, se presente) |

Il modulo **non impone alcuna deadline**: la risposta arriva quando
l'analisi è terminata, con il verdetto finale (il budget di esplorazione
interno resta comunque limitato). L'unica finestra di tempo è quella
gestita a monte dal chiamante (Front Door, ~60s di origin timeout): se
scatta, l'analisi completa comunque in background — il task è creato
esplicitamente e non dipende dalla connessione del client — e il
risultato (persistito su SQLite, cache 24h) viene restituito dalla
chiamata successiva. Una richiesta che arriva mentre un'analisi è già
in corso risponde onestamente `"verdict": "safe"`, `"confidence": 0.1`,
`"signature": "Analysis-Incomplete — Benign By Default"`; lo stesso vale
per un'analisi fallita (`Analysis-Failed`) o completata senza
classificazione.

## Test

```bash
pytest                # suite predefinita (nessuna chiamata di rete reale)
pytest -m integration # test con rete reale (httpbin.org)
```
