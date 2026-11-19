# GraphEngine

Uno strumento che prende in input un URL sospetto (es. segnalato come possibile
phishing) e lo analizza in automatico, seguendolo passo passo — redirect,
pagine intermedie, eventuali click — fino ad arrivare alla pagina finale.
Il risultato è un **grafo**: ogni pagina incontrata è un nodo, ogni redirect
o azione è un collegamento tra due nodi. Alla fine lo strumento dice se il
sito è probabilmente benigno, sospetto o phishing, e perché.

È un servizio indipendente: lo chiamano altri sistemi via HTTP (API
sincrona `GET /api/v1/analyze` oppure sottomissione asincrona + polling),
non viene mai importato direttamente nel loro codice. Le lookup su
piattaforme di threat intelligence interne (MISP/OpenCTI) restano a
carico del servizio chiamante.

## Come funziona, in breve

L'analisi è divisa in livelli (L0-L5), ciascuno con un compito preciso.
Ogni livello produce **evidenze** (segnali osservati, con un peso di rischio)
che si accumulano fino al verdetto finale:

| Livello | Cosa fa |
|---|---|
| **L0 — Ingestion** | Pulisce l'URL in ingresso: rimuove wrapper di sicurezza (es. link riscritti da gateway email), decodifica, normalizza |
| **L1 — Lessicale** | Analizza l'URL come testo: somiglianza con domini noti (typosquatting), entropia sospetta, pattern di infrastruttura tipici del phishing |
| **L2 — OSINT passivo** | Interroga fonti esterne senza toccare il sito: certificati SSL (ctlogs.dev), whois (RDAP), DNS, feed di minacce note (URLhaus). Le lookup su MISP/OpenCTI non fanno parte del motore: le gestisce a monte il servizio chiamante. Trova anche "domini fratelli" della stessa campagna |
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

# Come servizio HTTP (per integrazioni con servizi esterni)
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
verdetto e salta l'analisi — sia nella dashboard che nella risposta
dell'API esterna; in caso di conflitto vince il match più specifico (URL > dominio).

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
REST** (tranne `/health` e l'API esterna `/api/v1`, che ha la sua API
key): un 401 riporta alla schermata di accesso. Sulle route di
sottomissione e polling delle analisi (`POST /analyses`, `GET
/analyses[/...]`) la API key vale in alternativa al login, per i client
machine-to-machine.

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
- **Permessi di `./data` al primo deploy**: automatici — l'entrypoint del
  container parte come root solo per sistemare la directory dati (UID
  10001) e poi cede i privilegi prima di eseguire uvicorn. Se `./data`
  non esiste e viene creata come root dal demone Docker, il primo avvio
  la corregge da solo (il flag `:z` sul volume copre anche SELinux).
  Nessun chown manuale sull'host
- **Utente non-root**: il server non gira mai come root nel container
- **Un solo worker uvicorn**: SQLite ha un solo scrittore; per più
  throughput la strada è l'async dentro il singolo processo
- **Browser Chromium condiviso**: il lifespan dell'app mantiene un pool
  di browser Playwright riusati tra le richieste — nessun launch di
  Chromium per singola analisi
- **Autenticazione**: dashboard e API REST richiedono il login (utenti in
  SQLite, admin bootstrap al primo avvio — credenziali nel log se non
  valorizzate nel `.env`); l'API esterna richiede `X-API-Key`
  (`API_KEY` nel `.env`, più chiavi separate da virgola, 503 se
  assente). Solo `/health` è aperto (probe del container)
- **Concorrenza**: al massimo `MAX_CONCURRENT_ANALYSES` analisi in
  esecuzione insieme (default 4); le altre restano `queued` finché si
  libera uno slot

### Integrazione con un servizio esterno

L'API espone due modalità che lavorano sulla **stessa analisi** (stesso
target, stesso grafo, stesso verdetto in SQLite) — non sono due sistemi
separati. Entrambe si autenticano con l'header `X-API-Key`:

| Endpoint | Uso |
|---|---|
| `GET /api/v1/analyze?url=...` | Risposta **sincrona**: attende il completamento reale dell'analisi e porta sempre il verdetto finale (nessuna deadline imposta dal modulo) |
| `POST /analyses` + `GET /analyses/{id}` | Avvio asincrono (202 Accepted) e polling dello stato (`queued` → `running` → `done`/`error`) |
| `GET /analyses/{id}/verdict` | Lo stesso JSON di `/api/v1/analyze` per quell'analisi: da leggere a fine polling |
| `GET /analyses/{id}/graph` | **Il JSON completo**: target, tutti gli stati del grafo, le transizioni, le evidenze di ogni livello e il verdetto |

Il JSON mostrato dal CLI (`python -m graph_engine.cli <url>`) è lo stesso
contenuto di `GET /analyses/{id}/graph`.

#### Contratto di `GET /api/v1/analyze`

Il chiamante **passa l'URL in query string** e **attende che la risposta
contenga il JSON** del verdetto — non c'è un secondo passo. Il formato
della risposta è **identico** a quello della precedente integrazione
Trellix IVX (`/trellix/analyze`), così il servizio esterno è un
sostituto drop-in: cambiano solo il path e la variabile della chiave.

La route è **protetta da API key**: ogni richiesta deve portare
`X-API-Key` con una delle chiavi di `API_KEY` (se la variabile non è
configurata la route risponde **503** — configurazione mancante, mai
aperta; chiave assente o errata → **401**):

```bash
curl -G http://localhost:8000/api/v1/analyze \
     -H "X-API-Key: $API_KEY" \
     --data-urlencode "url=https://example.org/"
```

Tutto ciò che segue `url=` nella query string è l'URL da analizzare
(anche con `&`, `?` e `=` propri); il percent-encoding, anche multiplo,
viene decodificato.

Risposta (200, `Content-Type: application/json`) — verdetto binario avvolto
nella chiave `result` (`result.verdict` / `result.signature`):

```json
{
  "result": {
    "verdict": "safe",
    "confidence": 0.95,
    "signature": "No Threats Detected",
    "recommended_action": "allow",
    "reason": "Analisi completata — nessun indicatore di phishing rilevato."
  }
}
```

Campi di `result`:

| Campo | Valori | Significato |
|---|---|---|
| `result.verdict` | `safe` \| `malicious` | Il verdetto binario |
| `result.confidence` | 0.0–1.0 | Fiducia del verdetto (≥0.8-0.9 con verdetto definitivo; 0.1 sui rami non conclusivi: analisi fallita o senza classificazione) |
| `result.signature` | testo breve | Firma leggibile; su `safe` è sempre benigna (`No Threats Detected` o simile), mai "Phishing: …" |
| `result.recommended_action` | `allow` \| `block` | Azione raccomandata al chiamante |
| `result.reason` | testo | Motivazione leggibile (il `rationale` del classificatore, se presente) |

Comportamento:

- **Nessuna deadline** imposta dal modulo: la risposta arriva quando
  l'analisi è terminata, con il verdetto finale (il budget di
  esplorazione interno resta comunque limitato).
- **Cache 24h**: un URL già analizzato con successo nelle ultime 24 ore
  risponde subito con il verdetto salvato.
- **Richieste concorrenti sullo stesso URL**: la seconda si aggancia
  all'analisi già in corso invece di avviarne un'altra, ed entrambe
  ricevono lo stesso verdetto finale.
- **Disconnessione del chiamante**: se la connessione cade (es. timeout
  di un proxy), l'analisi completa comunque in background e il
  risultato viene restituito dalla chiamata successiva (cache).
- **Onestà**: un'analisi fallita risponde `"verdict": "safe"`,
  `"confidence": 0.1`, `"signature": "Analysis-Failed"`; una completata
  senza classificazione risponde `Analysis-Incomplete — Benign By
  Default`.
- **Whitelist/Blacklist**: un hit risponde subito con il verdetto
  forzato (`Whitelist-Override` / `Blacklist-Override`, confidenza 1.0).

## Test

```bash
pytest                # suite predefinita (nessuna chiamata di rete reale)
pytest -m integration # test con rete reale (httpbin.org)
```
