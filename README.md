# GraphEngine

Servizio che analizza un URL sospetto e restituisce un verdetto
**`safe` / `malicious`** con firma e motivazione. Apre l'URL in un browser
isolato, segue redirect, pagine intermedie e click fino alla pagina finale,
raccoglie segnali da più fonti e fa decidere un modello AI (Azure AI
Foundry), affiancato da alcune regole deterministiche.

È un servizio HTTP indipendente: i sistemi esterni lo chiamano via API
(`GET /api/v1/analyze`), gli analisti lo usano dalla dashboard web. Le
lookup su piattaforme di threat intelligence (MISP, OpenCTI, URLhaus) non
fanno parte del motore: restano al servizio chiamante. Verso OpenCTI il
motore può solo **scrivere**, su richiesta di un utente dalla dashboard.

Questo è il branch `standalone`. Il branch `main` conserva la versione
originale, integrata con Trellix IVX.

## Indice

- [Come funziona](#come-funziona)
- [Cosa non fa](#cosa-non-fa)
- [Avvio con Docker](#avvio-con-docker)
- [Configurazione](#configurazione)
- [API per i servizi esterni](#api-per-i-servizi-esterni)
- [Dashboard](#dashboard)
- [Esercizio in produzione](#esercizio-in-produzione)
- [Sviluppo e test](#sviluppo-e-test)

## Come funziona

Ogni analisi attraversa sei livelli. Ognuno produce **evidenze** (segnali
osservati con un peso), che arrivano tutte al classificatore finale.

| Livello | Cosa fa |
|---|---|
| **L0 — Ingestion** | Normalizza l'URL: rimuove i wrapper dei gateway di posta (es. Safe Links), riconosce gli URL "defanged" (`hxxp://`, `[.]`), decodifica la codifica, canonicalizza |
| **L1 — Lessicale** | Analizza l'URL come testo: somiglianza con domini di marchi noti (typosquatting), entropia, pattern tipici dell'infrastruttura di phishing |
| **L2 — OSINT passivo** | Interroga fonti esterne senza toccare il sito: certificati (ctlogs.dev, con i "domini fratelli" della stessa campagna), whois (RDAP), DNS |
| **L3 — Attivo leggero** | Richieste HTTP mirate: catena di redirect, favicon, impronta TLS (JARM) e confronto delle risposte con User-Agent diversi per scoprire il cloaking |
| **L4 — Esplorazione** | Un vero browser (Playwright/Chromium) naviga il sito: segue redirect HTTP, JS e meta refresh, supera gate CAPTCHA semplici, clicca i bottoni più plausibili (fino a 3 per pagina, in parallelo) e costruisce il **grafo degli stati**, con screenshot, DOM, HAR e campi dei form di ogni pagina (anche dentro gli iframe) |
| **L5 — Classificazione** | Azure AI Vision legge testo e marchi dagli screenshot; regole deterministiche decidono i casi certi; per il resto il modello Foundry valuta tutte le evidenze e restituisce verdetto, marchio imitato e una motivazione breve |

Le regole deterministiche di L5 coprono due casi:
- **Avviso del provider:** se il dominio analizzato mostra la pagina
  d'avviso di Cloudflare ("Suspected Phishing/Malware") o di Google Safe
  Browsing, il verdetto è subito malevolo, senza consultare il modello.
- **Pagina vuota o irraggiungibile:** se non c'è contenuto da giudicare, il
  verdetto è "dati insufficienti", con confidenza minima.

Il modello riconosce sia il furto di credenziali (pagine che imitano un
marchio e chiedono login, carte, dati personali) sia le **esche per
scaricare malware** (finti viewer, aggiornamenti o installer da domini non
ufficiali).

Alcuni accorgimenti di L4 contro le tecniche di evasione:
- attende i redirect JavaScript ritardati e le pagine che disegnano il form
  dopo alcuni secondi;
- confronta il DOM per riconoscere i cambi di stato anche nelle SPA, dove
  l'URL non cambia;
- esplora un secondo ramo con il profilo che ha ricevuto contenuti diversi,
  quando L3 rileva cloaking.

Ogni analisi viene salvata in SQLite e non sovrascrive mai le precedenti,
quindi lo storico di un URL resta consultabile. I dettagli di ogni livello
sono in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Cosa non fa

- **Non compila mai i form**: osserva e classifica, non invia credenziali,
  nemmeno finte.
- **Non risolve CAPTCHA reali**: al massimo attende l'auto-risoluzione o
  clicca una checkbox.
- **Non ricorda le analisi precedenti** quando classifica: ogni chiamata al
  modello parte da zero, perché un caso precedente non influenzi il giudizio.
- **Non interroga feed di reputazione** (MISP, OpenCTI, URLhaus): è compito
  del servizio chiamante.

## Avvio con Docker

Un solo container serve API e dashboard sulla stessa porta. Il deployment è
single-node su SQLite.

```bash
git clone -b standalone https://github.com/AxelSecurity/IVX-GraphEngine.git graph-engine
cd graph-engine

cp .env.example .env && chmod 600 .env   # poi compila le variabili (sezione Configurazione)

docker compose build      # include Chromium e le sue librerie
docker compose up -d
docker compose ps         # deve risultare (healthy)
curl http://localhost:8000/health
```

- **Dashboard:** `http://localhost:8000/dashboard`, utente `admin`.
- **Porta diversa:** `HOST_PORT=8080 docker compose up -d`.
- **Log:** `docker compose logs -f`.
- **Arresto:** `docker compose down`; i dati restano in `./data`.
- **Aggiornamento:** `git pull && docker compose up -d --build`.

## Configurazione

Tutta la configurazione sta nel `.env` accanto a `docker-compose.yml`.
`.env.example` contiene ogni variabile commentata.

**Accesso**

| Variabile | Default | A cosa serve |
|---|---|---|
| `API_KEY` | — (**obbligatoria**) | Chiavi per l'API esterna, separate da virgola (una per servizio chiamante). Senza, `/api/v1/analyze` risponde `503` |
| `DASHBOARD_ADMIN_USER` / `DASHBOARD_ADMIN_PASSWORD` | `admin` / casuale | Admin creato al primo avvio, solo se non esistono utenti. Senza password, quella generata viene stampata nel log |

**Classificazione (Azure)**

| Variabile | Default | A cosa serve |
|---|---|---|
| `AZURE_FOUNDRY_ENDPOINT`, `AZURE_FOUNDRY_AGENT_ID` | — | Modello di classificazione. Senza, si usa un fallback euristico |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | — | Service principal per Foundry. Senza, si usa `DefaultAzureCredential` |
| `AZURE_VISION_ENDPOINT`, `AZURE_VISION_KEY` | — | OCR e riconoscimento dei marchi sugli screenshot |
| `FOUNDRY_MAX_CONCURRENT` | `2` | Run Foundry contemporanei. Sul limite di quota si ritenta fino a 3 volte (10/20/40 s) |

**Fonti OSINT**

| Variabile | Default | A cosa serve |
|---|---|---|
| `CTLOGS_API_KEY` | — | Modalità API di ctlogs.dev (domini fratelli). Senza, si usa la modalità anonima |

**OpenCTI (pulsante della dashboard)**

| Variabile | Default | A cosa serve |
|---|---|---|
| `OPENCTI_URL`, `OPENCTI_API_KEY` | — | Abilitano "Invia a OpenCTI". La chiave deve poter creare Report e Indicator |
| `OPENCTI_TLP` | `TLP:AMBER` | Marcatura degli oggetti creati |
| `OPENCTI_AUTHOR` | `GraphEngine` | Organizzazione autore |
| `DASHBOARD_PUBLIC_URL` | — | URL pubblico della dashboard, per il link all'analisi nel Report |

**Prestazioni e risorse**

| Variabile | Default | A cosa serve |
|---|---|---|
| `MAX_CONCURRENT_ANALYSES` | `4` | Analisi in esecuzione insieme; le altre attendono in coda |
| `L4_PARALLEL_ACTIONS` | `3` | Azioni esplorate in parallelo per pagina (`1` = sequenziale) |
| `SCREENSHOT_MAX_HEIGHT` | `8000` | Altezza massima degli screenshot in pixel (Vision rifiuta oltre 16000) |
| `ARTIFACT_RETENTION_DAYS` | `30` | Giorni dopo cui si cancellano screenshot/DOM/HAR (`0` = mai). Il DB non viene toccato |
| `LOG_LEVEL` | `INFO` | Livello dei log |

## API per i servizi esterni

L'autenticazione usa l'header **`X-API-Key`**.

| Endpoint | Uso |
|---|---|
| `GET /api/v1/analyze?url=<url>` | **Sincrona**: risponde a fine analisi con il verdetto |
| `POST /analyses` → `GET /analyses/{id}` → `GET /analyses/{id}/verdict` | **Asincrona**: sottomissione (`202` con `id`), polling di `target.status` (`queued` → `running` → `done`/`error`), poi il verdetto nello stesso formato |
| `GET /analyses/{id}/graph` | Il JSON completo dell'analisi: stati, transizioni, evidenze, verdetto |
| `GET /health` | Stato del servizio, senza chiave |

```bash
curl -G https://<host>/api/v1/analyze \
     -H "X-API-Key: $API_KEY" \
     --data-urlencode "url=https://esempio-sospetto.com/login?id=42" \
     --max-time 360
```

```json
{
  "result": {
    "verdict": "malicious",
    "confidence": 0.92,
    "signature": "Phishing: Roundcube Impersonation",
    "recommended_action": "block",
    "reason": "Phishing Roundcube: la pagina su dominio non ufficiale (reliable-mail.com) chiede 'Username' e 'Password'; logo 'roundcube' rilevato nello screenshot."
  }
}
```

**Regole della richiesta**
- L'URL va **codificato e messo come ultimo parametro**: il server prende
  tutto ciò che segue `url=`.
- Sono accettati URL defanged e link riscritti dai gateway di posta.
- Lunghezza massima: 2048 caratteri.

**Decisione e firme**
- Si decide su `result.verdict`: `malicious` = bloccare.
- `signature` dice il tipo di minaccia:
  - `Phishing: <Marchio> Impersonation`
  - `Malware Download Lure: <Marchio> Impersonation`
  - `Flagged by <Provider>: Suspected Phishing|Malware`
  - `Blacklist-Override …`
  - `No Threats Detected`, ecc.
- `Analysis-Failed` e `Analysis-Incomplete — Benign By Default` sono `safe`
  con confidenza 0.1: non conclusivi.

**Tempi e comportamento**
- **Durata:** di solito 20–60 s; fino a circa 5 minuti sui siti con molti
  link. Il timeout client consigliato è **360 s**.
- **Cache:** un URL analizzato con successo nelle ultime 24 ore risponde
  subito. `POST /analyses` invece avvia sempre un'analisi nuova.
- **Richieste simultanee:** due richieste sullo stesso URL condividono la
  stessa analisi.
- **Disconnessione:** se il client si disconnette, l'analisi continua; la
  chiamata successiva riceve il risultato.
- **Whitelist/blacklist:** un URL o dominio in lista riceve subito il
  verdetto forzato (confidenza 1.0).
- **Errori:**
  - `401`: chiave assente o errata;
  - `422`: parametro `url` non valido;
  - `503`: `API_KEY` non configurata.

## Dashboard

`/dashboard`, accessibile con login: utenti in SQLite, ruoli `admin` e
`operator`, sessione di 12 ore.

- **Sottomissioni:** l'elenco delle analisi con filtri e ricerca, il form
  per sottomettere nuovi URL e la cancellazione multipla.
- **Dettaglio:** il grafo di esplorazione, gli screenshot di ogni stato, le
  evidenze per livello, il verdetto con la motivazione e il JSON esatto
  restituito dall'API.
- **Invia a OpenCTI:** solo sulle analisi `malicious`. Crea un Report con
  gli indicatori scelti nell'anteprima (URL analizzato, URL finale, dominio
  come host completo). Ogni analisi si invia una volta sola; dopo l'invio
  il riquadro mostra chi l'ha inviata e il link al Report.
- **Whitelist/Blacklist:** liste per dominio (dominio registrabile) e per
  URL. Un hit salta l'analisi e forza il verdetto; vince il match più
  specifico (URL su dominio).
- **Utenti** (solo admin): creazione, ruolo, password, eliminazione.
  L'ultimo admin è protetto, e cambiare password o ruolo chiude le sessioni
  attive dell'utente.

Gestione utenti da riga di comando, per le emergenze (es. password
dimenticata):

```bash
docker compose exec graph-engine python -m graph_engine.api.auth_cli list
docker compose exec graph-engine python -m graph_engine.api.auth_cli add operatore --role operator
docker compose exec graph-engine python -m graph_engine.api.auth_cli passwd admin
```

## Esercizio in produzione

- **Risorse:** 6–8 GB di RAM. Nei test reali il picco è stato 4,8 GB con
  4 analisi in parallelo. Per ridurre il consumo si abbassano
  `MAX_CONCURRENT_ANALYSES` o `L4_PARALLEL_ACTIONS`.
- **Rete in uscita:**
  - i siti da analizzare;
  - Azure (`*.services.ai.azure.com`, `*.cognitiveservices.azure.com`,
    `login.microsoftonline.com`);
  - `ctlogs.dev`, `data.iana.org` e i server RDAP;
  - OpenCTI, se usato.
- **Esposizione:**
  - dietro un reverse proxy con HTTPS;
  - timeout del proxy di almeno 360 s;
  - dashboard raggiungibile solo dalla rete interna.
- **Dati:** tutto sta in `./data` (DB `graph_engine.db`, artefatti, cache
  OSINT), montato nel container. I permessi si sistemano da soli al primo
  avvio e il server gira come utente non-root.
- **Retention:** un job giornaliero cancella gli artefatti più vecchi di
  `ARTIFACT_RETENTION_DAYS` e la cache OSINT scaduta. Il **backup di
  `./data/graph_engine.db`** resta a carico dell'infrastruttura.
- **Quota Foundry:** con molte analisi in parallelo può scattare il limite
  di token al minuto del deployment. Il motore ritenta, ma conviene
  dimensionare la quota (TPM) su Azure.
- **Log:** solo le righe utili (analisi, avvisi, chiamate esterne). Le
  librerie Azure restano al livello degli avvisi e i `GET /health` riusciti
  sono esclusi.

## Sviluppo e test

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium

uvicorn graph_engine.api.app:app --reload        # API + dashboard in locale
python -m graph_engine.cli <url> --classify      # analisi da riga di comando (JSON del grafo)
python -m graph_engine.cli --history <url>       # storico di un URL

pytest                                           # suite predefinita, senza rete reale
pytest -m integration                            # test con rete reale
```

- **Banco di prova di L4:** `tests/graph_engine/l4_fixtures.py` serve otto
  scenari locali (kit multi-pagina, SPA, gate, redirect JS ritardato,
  polling, fetch lenta, meta refresh, render ritardato).
  `test_l4_equivalence.py` verifica che il grafo esplorato resti identico a
  `l4_golden.json`; il golden si aggiorna solo con un motivo esplicito.
- **Benchmark di L4 su URL reali:** `scripts/bench_l4.py run <lista> -o
  out.json` e `compare before.json after.json`. Le liste stanno in
  `benchmarks/`, che git ignora.

Architettura, schemi dati e decisioni tecniche:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
