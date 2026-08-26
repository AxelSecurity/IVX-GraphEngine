# L4 — Dynamic State-Graph Engine — Architettura di riferimento

## Contesto

Le URL di phishing moderne raggiungono il payload finale solo dopo catene di redirect
eterogenee (HTTP, meta-refresh, JavaScript) e, nei kit AiTM, dopo interazioni utente reali
(click, navigazione gate). Il motore modella questo percorso come **grafo di stati
esplorabile**, non come catena lineare.

## Domain model

Cinque entità, implementate come modelli Pydantic v2. Persistenza: SQLite via `aiosqlite`
quando servirà (non in questo primo batch — per ora il grafo vive in memoria e viene
serializzato su richiesta). Artefatti binari (HAR, screenshot, DOM) su filesystem locale sotto
`data/graph_artifacts/<target_id>/<state_id>/`.

- **AnalysisTarget**: unità di lavoro. `id (UUID)`, `input_url`, `canonical_url`, `url_hash`,
  `status (queued|running|done|error)`, `root_state_id`, `created_at`.
- **State**: nodo del grafo. `id (UUID)`, `target_id`, `url`, `dom_hash` (DOM normalizzato,
  vedi sotto), `depth` (distanza dal root), `screenshot_ref`, `har_ref`. Unique su
  `(target_id, url, dom_hash)` — è il meccanismo di deduplica dei nodi.
- **Transition**: arco tipizzato tra due State. `id`, `target_id`, `from_state`, `to_state`,
  `kind` (enum, vedi sotto), `trigger` (dict/JSON: es. `{selector, coords, ua_profile}`), `ts`.
- **Evidence**: segnale atomico con provenance. `id`, `target_id`, `scope
  (target|state|transition)`, `scope_id`, `layer (L0..L5)`, `key`, `value`, `weight`,
  `produced_by`, `ts`.
- **Verdict**: esito aggregato. `target_id`, `classification
  (benign|suspicious|phishing — `aitm` removed, see §L5)`, `confidence`, `brand`, `kit_family`, `rationale`,
  `final_url`, `exfil_endpoint`.

### TransitionKind (enum)

| Valore | Semantica |
|---|---|
| `http_3xx` | Redirect HTTP via header Location |
| `meta_refresh` | Redirect via `<meta http-equiv=refresh>` |
| `js_location` | Assegnazione `window.location` / `location.replace` |
| `history_push` | Navigazione SPA senza cambio documento (pushState) |
| `click` | Transizione innescata da click su selettore registrato |
| `form_submit` | Invio form — spesso lo stage di harvesting |
| `new_tab` | Apertura nuovo contesto/tab (`target=_blank`, `window.open`) |
| `gate_solved` | Superamento di CAPTCHA / challenge anti-bot |
| `ws_message` | Cambio di stato guidato da messaggio WebSocket (tipico AiTM) |
| `cloaking_probe` | Collegamento dal root primario al root del ramo esplorato col profilo divergente (L3 cloaking) |

### Normalizzazione DOM (dom_hash)

Prima di calcolare l'hash (sha256), il DOM va normalizzato rimuovendo elementi puramente
dinamici che altrimenti impedirebbero di riconoscere lo stesso stato logico: nonce, timestamp,
token CSRF/session in attributi o testo, ordinamento non deterministico degli attributi.
Questo evita loop infiniti nel BFS e nodi duplicati per lo stesso stato reale.

## Motore di esplorazione

Nodo = `(URL, dom_hash)`. Arco = Transition tipizzata.

Esplorazione **BFS con budget**: `max_depth`, `max_nodes`, `timeout_s`. Set di visitati basato
su `dom_hash`. Gestisce nativamente branching, loop e percorsi alternativi.

```
frontier = queue([root_state])
visited  = set()
while frontier and within_budget():
    s = frontier.pop()
    if s.dom_hash in visited: continue
    visited.add(s.dom_hash)
    instrument_and_capture(s)           # HAR, screenshot, DOM
    for action in enumerate_actions(s):  # redirect impliciti + azioni interattive
        s2 = execute(action)
        record_transition(s, s2, action)
        if s2.dom_hash not in visited:
            frontier.push(s2)
    if stop_condition(s): break
```

### Cloaking probe (secondo ramo)

Quando L3 rileva cloaking, il contenuto servito al profilo divergente
(es. Googlebot) non è mai visibile al visitatore normale. Il motore
esplora quindi un SECONDO albero col profilo divergente:

1. L3 produce `cloaking_profile` (`cloaking_probe_profile` in
   `differential_fetch.py`): il profilo divergente con content_length
   maggiore, o `None` se nessun cloaking / divergenti tutti falliti.
2. `StateGraphExplorer.run(cloaking_profile=...)` — subito dopo la
   navigazione del root primario, PRIMA del BFS primario — apre un
   secondo context Playwright con user_agent/header del profilo
   divergente e naviga lo stesso `start_url`
   (`_explore_cloaking_branch`). L'ordine è deliberato: dopo il BFS
   primario il ramo non partirebbe mai sui target che reindirizzano a
   siti "infiniti" (es. Google), dove il primario consuma l'intero
   timeout globale.
3. Il nuovo root è collegato al root primario da una
   `Transition(cloaking_probe)`; il sotto-albero riusa lo stesso loop
   BFS (`_bfs_loop`) con max_depth ridotta a `min(2, budget.max_depth)`.
4. Budget residuo CONDIVISO con riserva di 2 nodi: se il ramo non
   partirebbe con abbastanza budget, viene registrata evidenza
   `cloaking_probe` status `skipped` e non si apre alcun context.
5. Replay: nessuna modifica necessaria — il goto del root sul context
   divergente incarna il cambio profilo; gli stati del ramo si
   raggiungono via click/gate sul context divergente stesso.

Il primario resta invariato: `root_state_id` e `final_url` del target
sono del primo pass. I leaf del ramo divergente entrano nel bundle L5
automaticamente (leaf = stato senza transizioni outbound).

## Interaction engine (fasi successive, non in questo primo batch)

- **Actionable scoring**: elementi interagibili (`button, a, [role=button],
  input[type=submit]`) ordinati per punteggio = keyword d'azione (verify, continue, sign in,
  unlock, view document, proceed, open) + salienza visiva (dimensione/posizione bounding box)
  + posizione nel DOM. Click in ordine di punteggio, attesa navigazione/mutazione, ricorsione.
- **Gate solver**: rilevamento e gestione di challenge anti-bot (Turnstile/hCaptcha
  interattivo, banner cookie, splash "click to continue"). Non prevede bypass crittografico di
  CAPTCHA, solo navigazione di gate standard.
## Evasione (fasi successive)

Profilo coerente (UA + timezone + locale + Accept-Language + geo proxy), determinato dal
livello L3 (differential fetching, non ancora implementato). Per ora il motore usa un profilo
di default configurabile.

## Stop condition

Brand impersonato identificato E endpoint di raccolta isolato, OPPURE budget esaurito.

## Integrazione futura con IntelIVX

Questo motore è un servizio indipendente. L'integrazione con IntelIVX (repo separato) avverrà
via chiamata HTTP o coda messaggi, mai via import diretto — mantiene i due progetti
disaccoppiati e permette di far evolvere questo motore senza rischiare regressioni
sull'analyzer esistente, già in produzione.

## Decisioni di scope

### Rimozione della credential injection (2026-08-09)

L'injection di credenziali canary (email/password/OTP) è stata rimossa dal motore.
Lo scopo del progetto è la **classificazione** di siti di phishing tramite navigazione
ed esplorazione del grafo degli stati — non l'inserimento di dati, nemmeno finti.

La decisione è motivata da:
1. **Focus**: la classificazione si basa su indicatori osservabili passivamente (URL,
   DOM, redirect, infrastruttura), non sull'interazione con form.
2. **Sicurezza**: anche con credenziali canary su dominio `.invalid`, l'invio di dati
   verso endpoint di phishing solleva questioni operative e legali.
3. **Semplicità**: rimuovere il sottosistema di injection riduce la superficie di
   codice e i casi di test, accelerando l'iterazione sul core engine.

I file rimossi:
- `graph_engine/credential_injection.py`
- `graph_engine/canary_identity.py`
- `tests/graph_engine/test_credential_injection.py`

Il codice rimosso da `graph_engine/explorer.py`:
- Import dei moduli di credential injection
- Blocco di credential injection nel BFS loop (~55 linee)
- Branch `form_submit` in `_replay_to_state_impl` (~65 linee)
- Metodo `_handle_credential_submit` (~90 linee)

Il valore `TransitionKind.form_submit` è preservato nell'enum per retrocompatibilità
e possibile uso futuro, ma non viene più prodotto dal motore.

## L5 — Classificazione

Il livello L5 trasforma i dati grezzi raccolti durante l'esplorazione L4 in un
**Verdict** strutturato: `classification` (benign/suspicious/phishing), `confidence`
(0-1), `brand`, `kit_family`, `rationale`.

### Pipeline a due stadi

1. **Prefiltro deterministico** (`graph_engine/classifier/prefilter.py`):
   intercetta casi banalmente inconclusivi (1 stato senza testo visibile, errore
   non gestito senza altri segnali) e restituisce direttamente un Verdict
   `suspicious` a bassa confidenza, senza chiamare il modello. È
   deliberatamente debole perché L1 (reputazione dominio, età registrazione)
   e L2 (blacklist, certificate transparency) non esistono ancora — quando
   saranno costruiti, questo filtro intercetterà molti più casi.

2. **Classificatore Foundry** (`graph_engine/classifier/foundry_classifier.py`):
   chiama un Azure AI Foundry Agent con un *evidence bundle* compatto. Il
   modello riceve solo osservazioni strutturate — mai DOM grezzo, mai HAR
   completi, mai immagini allegate. Dal 2026-08-26 l'attach degli
   screenshot è stato RIMOSSO del tutto: il modello configurato
   (gpt-5-mini) rifiuta gli image content block e il contenuto visivo
   arriva comunque come TESTO nel bundle (OCR + Brand Detection via
   Azure AI Vision — vedi sotto). La firma è `classify(bundle)` senza
   parametri immagine.

### Evidence bundle (compatto)

Il bundle (`graph_engine/classifier/evidence_bundle.py`) contiene:
- Metadati dell'esplorazione: `input_url`, `canonical_url`, `num_states`,
  `num_transitions`, `max_depth_reached`
- Conteggi per tipo di transizione (`transition_kinds_seen`)
- Flag booleani da Evidence: `had_gate`, `had_navigation_error`,
  `had_replay_fallback`, `had_unhandled_error`
- Per ogni stato foglia (senza transizioni in uscita): URL, titolo pagina,
  testo visibile estratto (troncato a ~1500 caratteri, strip di
  script/style/tag), risultato di `scan_form_fields()` (sola lettura),
  più i campi di arricchimento visivo `ocr_text` e `brands` (vedi sotto)

### Arricchimento Azure AI Vision (OCR + Brand Detection)

`graph_engine/classifier/vision_analysis.py` arricchisce gli screenshot
degli stati foglia usando la risorsa Azure AI Vision **già esistente**
(`aigpt-pr-it-intelivx-resource.cognitiveservices.azure.com`, regione
italynorth — nessuna risorsa nuova da creare). Due capacità, due
superfici API DIVERSE della stessa risorsa:

- **OCR** — SDK moderna `azure-ai-vision-imageanalysis` (client async
  nativo `azure.ai.vision.imageanalysis.aio.ImageAnalysisClient` +
  `VisualFeatures.READ`). Cattura il testo renderizzato via
  canvas/immagini, invisibile al DOM.
- **Brand Detection** — REST legacy v3.2
  `POST {endpoint}/vision/v3.2/analyze?visualFeatures=Brands`, perché la
  SDK moderna (API v4) NON espone più i brand. Autenticazione a chiave
  della risorsa (header `Ocp-Apim-Subscription-Key` — diversa dall'AAD
  usata per Foundry) e body `application/octet-stream` con i byte
  grezzi del file: gli screenshot sono PNG locali su disco, non URL
  pubblici.

I risultati entrano nel bundle come campi **separati** per ogni stato
foglia: `ocr_text` e `brands` non vengono MAI fusi con `visible_text`
— la provenienza resta distinguibile. Nel prompt per Foundry le tre
fonti sono etichettate distintamente ("Testo visibile nel DOM:",
"Testo rilevato via OCR nello screenshot:", "Brand rilevati nello
screenshot:"). Il prefilter considera anche `ocr_text` prima di
dichiarare "nessun testo visibile" (una pagina canvas-only NON è
"dati insufficienti").

Contratto di resilienza: nessuna funzione del modulo lancia mai
eccezioni (tornano dict con chiave `error`); le due chiamate girano in
parallelo con `asyncio.gather(..., return_exceptions=True)` — il
fallimento di una non blocca l'altra; senza `AZURE_VISION_ENDPOINT` +
`AZURE_VISION_KEY` (property `vision_configured`) non viene tentata
alcuna chiamata di rete.

### `scan_form_fields` — inventario passivo

`graph_engine/classifier/form_inventory.py` enumera input/select/textarea
visibili senza MAI compilare, cliccare o inviare. Per ogni campo restituisce
`{tag, type, name_or_id, nearby_label_text}`. Esclude hidden, submit, button,
checkbox, radio, file. Serve come segnale: "questa pagina chiede email,
password, numero di carta, CVV, Codice Fiscale".

### Vincolo stateless — NON NEGOZIABILE

Ogni chiamata a `classify()` crea un **nuovo thread** Foundry e lo cancella
dopo l'uso. Nessun `thread_id` viene mai riutilizzato tra analisi diverse.

**Motivazione** (bug storico, 2026-08): durante i primi test, la memoria
cross-sessione del Foundry Agent causava falsi positivi: il contesto di un
caso phishing precedente (form con campi email+password) "inquinava"
l'analisi di un URL benigno successivo, portando a verdict `phishing` ad
alta confidenza per siti legittimi. L'isolamento stateless è l'unica
garanzia di correttezza.

### Autenticazione Foundry — ClientSecretCredential o DefaultAzureCredential

Il classificatore seleziona la credential dalla configurazione
(`settings.service_principal_configured`):

- **Service principal completo** (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` +
  `AZURE_CLIENT_SECRET` nel `.env`) → `ClientSecretCredential` con quei
  valori: autenticazione stabile e riproducibile, senza dipendere da
  sessioni interattive.
- **Altrimenti** → `DefaultAzureCredential` (Azure CLI loggata, managed
  identity, ecc.).

NOTA: pydantic-settings NON esporta i valori del `.env` in `os.environ` —
`EnvironmentCredential` non li vedrebbe mai; è `foundry_classifier.py` a
passarli esplicitamente a `ClientSecretCredential`. Prima di questo
cambiamento i run remoti richiedevano `set -a; source .env; set +a` o
`az login`.

### Semplificazione del Classification enum

Il valore `aitm` è stato rimosso da `Classification`. La classificazione
riguarda *cosa* è il sito (benigno, sospetto, phishing), non *come*
avviene l'exfiltration (AiTM, reverse-proxy, form POST diretto). Il kit
family e la tecnica di attacco vanno nei campi `kit_family` e `rationale`,
non nel classification enum.

### System prompt

Il system prompt del classificatore (`graph_engine/classifier/system_prompt.txt`)
impone tre vincoli non negoziabili:
1. **Evidence grounding**: ogni affermazione nella motivazione deve
   riferirsi esplicitamente a un dato presente nel bundle.
2. **No invenzione**: se un'informazione non è nel bundle, non va assunta.
3. **Dati insufficienti**: se il bundle è troppo scarso, restituire
   `suspicious` con confidence ≤ 0.3 esplicitamente.

## L2 — Passivo / OSINT

Il livello L2 raccoglie informazioni da fonti esterne senza interagire con
il target. Tutte le query sono in **parallelo** (`asyncio.gather` con
`return_exceptions=True`): un fallimento su una fonte non blocca mai le altre.

### Fonti attive

| Fonte | Tipo | Endpoint | Cache TTL |
|---|---|---|---|
| **crt.sh** | Certificate Transparency | `https://crt.sh/?q=<domain>&output=json` | 6 ore |
| **RDAP** | WHOIS moderno (via bootstrap IANA) | `https://data.iana.org/rdap/dns.json` → server TLD-specifico | 24 ore |
| **DNS** | Risoluzione A/AAAA | `loop.getaddrinfo` (asyncio nativo, nessuna dipendenza esterna) | 1 ora |

### Adapter predisposti (disabilitati di default)

| Provider | Variabili d'ambiente richieste | Stato |
|---|---|---|
| **URLhaus** | `URLHAUS_API_KEY` | Disabilitato — si attiva automaticamente quando la chiave è presente |
| **MISP** | `MISP_URL` + `MISP_API_KEY` | Disabilitato — si attiva automaticamente quando entrambe le variabili sono presenti |
| **OpenCTI** | `OPENCTI_URL` + `OPENCTI_API_KEY` | Disabilitato — stessa logica |

URLhaus richiede ora una Auth-Key gratuita (registrazione su
https://auth.abuse.ch/), inviata nell'header `Auth-Key` di ogni
richiesta verso `https://urlhaus-api.abuse.ch/v1/url/` (endpoint
invariato). Senza chiave il provider restituisce `skipped: "not
configured"` senza tentare alcuna chiamata HTTP — stesso pattern di
MISP/OpenCTI. Una risposta 401 con chiave configurata (chiave invalida
o scaduta) produce evidenza `provider_unavailable`, mai un'eccezione.

Per attivare URLhaus, MISP o OpenCTI, basta impostare le variabili
d'ambiente corrispondenti. Nessuna modifica al codice necessaria: il
`registry.py` rileva le variabili a runtime e istanzia i provider.

### Segnali estratti

- **Domini fratelli di campagna** (`sibling_domains`): dalla SAN list
  aggregata di crt.sh, deduplicata, con il dominio interrogato escluso.
  Limite 50 domini; se il numero reale è superiore, viene impostato
  `truncated: true` con il conteggio reale in `total_siblings`.
  Questo è il pivot a più alto valore secondo l'architettura originale.

- **Età del dominio** (`domain_age_days`): dal record RDAP. Soglie:
  < 30 giorni → peso 0.35 (sospetto), 30-90 giorni → peso 0.15 (moderato),
  > 90 giorni → nessuna penalizzazione (dominio stagionato).

- **Reputation hit** (`reputation_hit`): URL presente in un feed di
  minacce (es. URLhaus). Peso 0.50 (il più alto).

- **Record A** (`dns_a_records`): indirizzi IPv4 risolti per il dominio.
  Peso 0.0 (informativo). Colma una lacuna IOC: gli IP servono ai
  consumatori a valle (Horus/IntelIVX) per correlazione infrastrutturale,
  geolocalizzazione, e lookup ASN.

- **Record AAAA** (`dns_aaaa_records`): indirizzi IPv6 risolti per il
  dominio. Peso 0.0 (informativo). Stessa semantica dei record A.

- **Provider unavailable** (`provider_unavailable`): per ogni fonte
  che fallisce, evidenza con weight=0.0 (informativa, non contribuisce
  al rischio).

### Pesi del passive_risk_score

| Peso | Valore | Condizione |
|---|---|---|
| `_W_DOMAIN_AGE_YOUNG` | 0.35 | Dominio < 30 giorni |
| `_W_DOMAIN_AGE_MODERATE` | 0.15 | Dominio 30-90 giorni |
| `_W_SIBLING_DOMAINS` | 0.30 | Presenza domini fratelli nella SAN list |
| `_W_REPUTATION_HIT` | 0.50 | URL presente in feed di minacce |

Il punteggio è clampato a [0, 1]. **MAI** penalizzare per l'assenza di
segnale — solo per la presenza.

**Single source of truth**: lo score aggregato è derivato dai `weight`
delle Evidence — stessa fonte, non due percorsi che condividono solo le
costanti:

```python
risk = sum(ev["weight"] for ev in evidence)
passive_risk_score = round(min(1.0, risk), 4)
```

Ogni segnale contribuente porta `weight > 0` sulla propria Evidence;
le evidenze informative (`provider_unavailable`, `dns_a_records`,
`dns_aaaa_records`) hanno `weight=0.0` e non pesano.  Non esiste alcun
accumulo parallelo di `risk` accanto alla costruzione delle Evidence:
un solo posto decide il contributo di ogni segnale, quindi i due non
possono divergere.  La proprietà è garantita per costruzione da un
test strutturale (`TestRiskScoreDerivedFromWeights` in
`tests/graph_engine/test_osint/test_analyzer.py`) che verifica
`passive_risk_score == sum(weight)` (salvo clamp) su scenari diversi,
e fallirebbe se qualcuno reintroducesse due percorsi paralleli.

### Cache

Cache filesystem sotto `data/osint_cache/<provider>/<hash>.json`.
TTL differenziati per tipo di dato:

- RDAP: 24 ore (i dati WHOIS cambiano molto raramente)
- crt.sh: 6 ore (nuovi certificati possono comparire)
- URLhaus: 1 ora (feed di minacce, più dinamico)
- IANA bootstrap: 30 giorni (la mappatura TLD→server RDAP è stabile)

La cache non è mai bloccante: un fallimento di scrittura viene
silenziosamente ignorato.

### Bootstrap RDAP

Il file IANA `https://data.iana.org/rdap/dns.json` viene scaricato (con
cache lunga 30 giorni) per mappare ogni TLD al suo server RDAP. **Nessuna
mappatura TLD→server è hardcodata** — stesso principio del fix tldextract
per i TLD a due componenti.

### Architettura del package

```
graph_engine/osint/
    __init__.py
    analyzer.py          — orchestratore parallelo
    cache.py             — cache filesystem con TTL
    certificate_transparency.py — crt.sh
    dns_resolve.py       — risoluzione DNS A/AAAA (asyncio nativo)
    rdap.py              — RDAP con bootstrap IANA
    reputation/
        __init__.py
        base.py          — ReputationProvider (ABC)
        urlhaus.py       — URLhaus (richiede Auth-Key)
        misp.py           — MISP adapter (disabilitato di default)
        opencti.py        — OpenCTI adapter (disabilitato di default)
        registry.py       — get_enabled_providers()
```

## L3 — Attivo low-interaction

Il livello L3 interagisce ATTIVAMENTE con il target, ma solo a bassa intensità:
richieste HTTP senza esecuzione JavaScript e una connessione TLS per il
fingerprinting JARM. Non viene mai eseguito codice della pagina, non vengono
compilati form, non viene aperto un browser.

### Fonti

| Fonte | Tipo | Target | Rischio |
|---|---|---|---|
| **Redirect chain** | HTTP manuale | L'URL stesso | Minimo — richieste HEAD/GET senza cookie |
| **Favicon hash** | HTTP GET | `/favicon.ico` | Minimo — una richiesta statica |
| **JARM** | Connessione TLS | `hostname:443` | Basso — 10 Client Hello TLS senza completare l'handshake |
| **Differential fetch** | HTTP parallelo | L'URL stesso | Basso — 4 richieste GET con User-Agent diversi |

### Redirect chain (`graph_engine/active/redirect_chain.py`)

Segue MANUALMENTE i redirect HTTP con `follow_redirects=False`, registrando
per ogni hop: `status_code`, `location`, `server` header, e i **nomi** dei
cookie (MAI i valori). Si ferma a `max_hops=10` o quando arriva una risposta
non-redirect. Gli errori di rete diventano un hop con `{"error": "..."}` —
mai eccezioni verso il chiamante.

### Favicon hash (`graph_engine/active/favicon.py`)

Prova `/favicon.ico` sulla root del dominio. L'algoritmo hash è ESATTAMENTE
quello di Shodan/Censys:

1. Scarica i byte grezzi del favicon
2. `encoded = base64.encodebytes(raw_bytes)` — **NON** `base64.b64encode`!
   `encodebytes` produce output MIME-style con a-capo ogni 76 caratteri.
   Se si usa `b64encode` (plain, senza a-capo) l'hash mmh3 risulterà DIVERSO.
   Il test `test_base64_encodebytes_vs_b64encode_produce_different_hashes`
   verifica ATTIVAMENTE questa distinzione.
3. `h = mmh3.hash32(encoded)` — MurmurHash3 32-bit signed. `mmh3.hash32`
   restituisce già un intero con segno, non serve conversione esplicita.

**LIMITAZIONE ATTUALE**: solo `/favicon.ico` sulla root del dominio. Il
parsing di `<link rel="icon">` dal body HTML non è ancora implementato.
Documentato nel codice con un commento.

### JARM (`graph_engine/active/jarm.py`)

**Implementazione**: vendorizzata da [Salesforce/jarm](https://github.com/salesforce/jarm)
(BSD 3-Clause) in `graph_engine/active/vendor/jarm_reference.py`. La logica
di costruzione del TLS ClientHello è PRESERVATA ESATTAMENTE dall'originale —
è stata rifattorizzata SOLO per:
- rimuovere argparse e print (da CLI a libreria)
- rendere host/port parametri espliciti
- rimuovere il supporto proxy SOCKS5

Il PyPI package `jarm` NON è il tool Salesforce (è un package non correlato
di "rayan haddad"). Per questo motivo è stato necessario vendorizzare.

**Esecuzione asincrona**: la computazione JARM è sincrona e basata su socket
grezzi. Viene wrappata con `asyncio.to_thread()` per non bloccare l'event
loop, con un timeout esplicito (`timeout_s + 2s` di margine).

### Differential fetch (`graph_engine/active/differential_fetch.py`)

Quattro profili HTTP predefiniti:

| Profilo | User-Agent | Note |
|---|---|---|
| `desktop_chrome` | Chrome 125 su Windows 10 | Default L4 |
| `mobile_safari` | Safari su iPhone iOS 17.5 | Mobile |
| `bot_googlebot` | Googlebot 2.1 | Crawler |
| `no_referer_desktop` | Chrome 125 su Windows 10 | Nessun Referer |

Tutti i profili vengono eseguiti IN PARALLELO (`asyncio.gather`). Per
ciascuno si registra: `status_code`, `final_url`, `content_length`,
`body_sha256`.

**Cloaking detection**: confronta status code, URL finali e hash dei body
tra tutti i profili. Se divergono, `cloaking_detected=True` e viene
raccomandato il profilo che ha ricevuto la risposta "più ricca"
(content_length maggiore tra i profili non divergenti).

**Recommend profile**: restituisce un dict `{user_agent, headers}` pronto
per `browser.new_context()` di Playwright in L4.

**Cloaking probe profile** (`cloaking_probe_profile`): il profilo
divergente più ricco (content_length maggiore, esclusi quelli con
`error`) da esplorare come secondo ramo L4. Ritorna `None` quando non
c'è cloaking o nessun divergente ha avuto successo.

### Orchestratore (`graph_engine/active/analyzer.py`)

`analyze(canonical_url)` esegue tutte e quattro le sonde IN PARALLELO.
JARM ha bisogno solo di hostname/porta, quindi può partire insieme alle
altre. Un fallimento su una sonda non blocca MAI le altre
(`asyncio.gather` con `return_exceptions=True`).

**Segnali estratti**:
- `redirect_hop_count` — numero di hop e redirect (peso: 0.05 se >= 3 redirect)
- `excessive_redirects` — >= 5 redirect (peso: 0.15)
- `unusual_server_header` — server header non standard (peso: 0.05)
- `favicon_hash` — hash mmh3 del favicon (peso: 0.05)
- `jarm_fingerprint` — JARM hash a 62 caratteri (peso: 0.10)
- `cloaking_detected` — cloaking rilevato tra profili (peso: 0.25)
- `differential_fetch_summary` — riepilogo profili (peso: 0.0, informativo)
- `active_probe_error` — fallimento di una sonda (peso: 0.0, informativo)

### Wiring L3 → L4

Il `recommended_profile` prodotto dall'analyzer L3 viene passato a
`StateGraphExplorer.run(profile=...)`. Il profilo contiene
`user_agent` e `headers`:

- `user_agent` → `browser.new_context(user_agent=...)`
- `headers` → `browser.new_context(extra_http_headers=...)`

Playwright applica questi header a OGNI richiesta HTTP del browser,
permettendo di emulare il profilo che L3 ha determinato essere il più
adatto per quel target (es. il profilo che ha ricevuto la risposta
"più ricca" in caso di cloaking).

In caso di cloaking, l'analyzer produce anche `cloaking_profile` che
viene passato a `StateGraphExplorer.run(cloaking_profile=...)` per il
secondo ramo (vedi "Cloaking probe (secondo ramo)" nella sezione del
motore di esplorazione).

### Architettura del package

```
graph_engine/active/
    __init__.py
    analyzer.py              — orchestratore parallelo
    redirect_chain.py        — tracciamento manuale HTTP redirect
    favicon.py               — hash favicon stile Shodan/Censys
    jarm.py                  — wrapper asincrono JARM
    differential_fetch.py    — fetch multi-profilo + cloaking detection
    vendor/
        __init__.py
        jarm_reference.py    — implementazione Salesforce (BSD 3-Clause)
```

### Dipendenze

- `mmh3>=5.0` — MurmurHash3 per favicon hash
- `httpx` — già presente per L2, usato anche per le richieste HTTP L3
- Nessuna dipendenza aggiuntiva per JARM (socket stdlib + hashlib)

## Persistenza SQLite

A partire da Agosto 2026, ogni esplorazione viene salvata automaticamente in un
database SQLite append-only (`data/graph_engine.db`). Il salvataggio non è
opzionale né dietro un flag — ogni run produce una nuova riga in
`analysis_target`.

### Principio append-only

- Ogni analisi è un **nuovo record** con un suo UUID (`analysis_target.id`).
- Due analisi dello stesso URL sono indipendenti — condividono lo stesso
  `url_hash` (SHA-256 del canonical URL) per il raggruppamento storico, ma
  hanno UUID diversi.
- Nessun UPDATE su righe esistenti — solo INSERT OR REPLACE (idempotente)
  durante il salvataggio.

### Schema

```
analysis_target  (id PK, input_url, canonical_url, url_hash INDEXED,
                  final_url, status, root_state_id, created_at)

state            (id PK, target_id FK→analysis_target ON DELETE CASCADE,
                  url, dom_hash, depth, screenshot_ref, har_ref)

transition       (id PK, target_id FK→analysis_target ON DELETE CASCADE,
                  from_state, to_state, kind, trigger JSON, ts)

evidence         (id PK, target_id FK→analysis_target ON DELETE CASCADE,
                  scope, scope_id, layer, key, value, weight, produced_by, ts)

verdict          (target_id PK+FK→analysis_target ON DELETE CASCADE,
                  classification, confidence, produced_by, brand,
                  kit_family, rationale, final_url, exfil_endpoint)
```

Lo schema rispecchia esattamente `graph_engine/models.py`. Tutti gli UUID sono
salvati come TEXT, i datetime in ISO-8601, gli enum come TEXT.

### Repository async

`graph_engine/storage/repository.py` — operazioni CRUD via `aiosqlite`:

- **`save_target()`** — un'unica transazione: target + stati + transizioni
  + evidence + verdict. Idempotente sull'UUID del target (`INSERT OR REPLACE`).
- **`get_target_by_id()`** — grafo completo (join delle 5 tabelle) per un
  target UUID.
- **`get_history_for_url_hash()`** — riepilogo compatto di tutte le analisi
  per un dato `url_hash`, ordinate per `created_at` decrescente.
- **`get_latest_for_url_hash()`** — solo l'analisi più recente, formato completo.

### CLI

- `--history <URL_OR_HASH>` — stampa lo storico esistente per quell'URL e termina
  senza eseguire una nuova analisi.
- Ogni `python -m graph_engine.cli <url>` salva automaticamente al termine
  dell'esplorazione — nessun flag aggiuntivo richiesto.

## API HTTP (FastAPI)

L'API espone la pipeline L0→L5 come endpoint REST asincroni. È il punto
d'ingresso per tutti i consumatori futuri (dashboard web, tool interni)
diversi dal wrapper Trellix.

### Design

- **Nessuna coda esterna** (no Redis, no Celery). Lo stato dei job è
  persistito su SQLite tramite `AnalysisTarget.status`.
- **Lifecycle**: `queued` → `running` → `done` | `error`.
- **Fire-and-forget**: la POST risponde subito con 202; il job gira in
  background via `asyncio.create_task`.
- **Race-free**: il target viene salvato come `queued` (con `await`) prima
  di lanciare il task — un GET immediato sull'id restituito non darà mai 404.
- **Browser Playwright**: aperto solo durante L4 e chiuso prima di L5 (il
  classificatore non ha bisogno del browser).
- **Runner riusabile**: `run_full_analysis(raw_url, budget, classify)` è
  usato sia dalla route POST che dal wrapper Trellix.

### Endpoint

| Metodo | Path | Descrizione | Status code |
|---|---|---|---|
| `POST` | `/analyses` | Submit a new analysis | 202 |
| `GET` | `/analyses/{id}` | Analysis status + counts | 200 / 404 |
| `GET` | `/analyses/{id}/graph` | Full graph (states, transitions, evidence, verdict) | 200 / 404 |
| `GET` | `/analyses/{id}/artifacts` | List artifact files (screenshot, DOM, HAR) | 200 / 404 |
| `GET` | `/analyses/history?url=` or `?url_hash=` | Past analyses for the same URL | 200 / 422 |
| `GET` | `/health` | Health check + running job count | 200 |

### Avvio

```bash
uvicorn graph_engine.api.app:app --reload
```

L'app va avviata dalla root del progetto (i path `data/` sono relativi).

### Architettura del package

```
graph_engine/api/
    __init__.py
    app.py               — FastAPI app factory (create_app)
    routes.py            — 6 endpoint, factory con db_path/artifact_root iniettabili
    pipeline_runner.py   — run_full_analysis(): orchestrazione L0→L5, lifecycle status
    schemas.py           — modelli Pydantic request/response (distinti dal dominio)
    fast_profile.py      — budget/timeout del profilo fast Trellix (vedi sotto)
    allowlist.py         — tabella allowlist/blacklist con matching eTLD+1
    trellix_verdict.py   — mapping binario + signature + response builder
    routes_trellix.py    — GET /trellix/analyze (wrapper sincrono Trellix)
```

### Test

I test API usano `httpx.AsyncClient` + `ASGITransport` (nessun server reale).
La pipeline è interamente mockata (nessun browser Playwright, nessuna rete):

- **`FakePlaywright`** sostituisce `async_playwright()`
- **`FakeExplorer`** sostituisce `StateGraphExplorer`
- **`_fake_l2` / `_fake_l3`** sostituiscono gli analyzer OSINT e Active
- L1 (lexical) è sync e non ha bisogno di mock async
- `ingest()` (L0) **non** è mockato — è puro e offline

I test verificano:
- La race 202→GET 404 è chiusa
- Il lifecycle status (queued → done) funziona
- L'error path salva lo stato `error` con evidence `pipeline_error`
- Gli stati parziali prodotti da L4 sopravvivono a un fallimento di L5
  (il `target_id` API è iniettato in `explorer.run()` fin dall'inizio)
- Gli endpoint history, artifacts e health rispondono correttamente

### Limitazioni

- **Multi-worker**: se si usano più worker uvicorn, i job girano nel worker
  che ha ricevuto la richiesta. Lo stato su SQLite è la fonte di verità
  condivisa, ma non c'è bilanciamento del carico tra worker.
- **Nessuna autenticazione**: l'API è pensata per uso interno. Autenticazione
  e autorizzazione vanno aggiunte prima di esporla su rete.
- **Nessuna cancellazione**: non esiste un endpoint `DELETE /analyses/{id}`.

## Wrapper Trellix

Il wrapper espone un endpoint **sincrono** compatibile con Trellix IVX:
`GET /trellix/analyze?url=...`. Trellix invia URL a un endpoint sincrono e
si aspetta una risposta binaria `safe`/`malicious` entro ~60 secondi —
un profilo radicalmente diverso da quello dell'API REST asincrona.

### Principio guida: fire-and-continue, mai bloccare

Il wrapper **non deve mai bloccare Trellix** oltre la sua deadline. Il
pattern è **fire-and-continue**:

1. L'analisi parte come background task (`asyncio.create_task`)
2. La route attende al massimo 48s con `asyncio.wait([task], timeout=48)`
   — **NON** `asyncio.wait_for`, che cancellerebbe il task
3. Se il task non completa entro la finestra, la risposta è
   `safe` + signature `Analysis-Incomplete — Benign By Default` con un
   reason che dichiara esplicitamente che l'analisi continua in background
4. Il task **continua** in background e persiste il risultato su SQLite;
   la richiesta successiva per lo stesso URL (cache 24h) lo troverà

La scelta "in dubbio → safe" è deliberata: meglio un falso negativo che
bloccare un sito legittimo su un'analisi incompleta.

### Flow della route

```
GET /trellix/analyze?url=<double-encoded>
    │
    ├─ 0. Auth Bearer opzionale (TRELLIX_API_TOKEN)
    │     — confronto constant-time (secrets.compare_digest)
    │     — se la variabile non è configurata, nessuna auth
    │
    ├─ 1. unquote() aggiuntivo (Trellix invia URL doppio-encodati)
    │
    ├─ 2. Allowlist/blacklist → risposta immediata (confidence 1.0)
    │
    ├─ 3. Cache 24h: get_latest_for_url_hash + status=done + verdict
    │     → risposta immediata dal DB
    │
    └─ 4. Fire-and-continue con budget FAST_BUDGET
          (vedi fast_profile.py)
```

### Verdetto binario

| Classification | Verdetto Trellix | Azione |
|---|---|---|
| `benign` | `safe` | `allow` |
| `suspicious` | `safe` | `allow` |
| `phishing` | `malicious` | `block` |

La signature testuale ha una catena di priorità:
1. **Brand impersonation** — brand noto trovato nell'evidenza L1
   `typosquat` o in `verdict.brand` → `Phishing: {brand} Impersonation`
2. **Gate bypass** — evidenza `gate_solved` → `Suspicious Gate Bypass Detected`
3. **Credential harvesting** — evidenza L1 `aitm_email_payload` o
   `kit_family` con "aitm"/"harvest" → `Credential Harvesting Detected`
4. **Firma generica** basata sulla classificazione

Nota: i form fields NON sono persistiti come evidenza
(`pipeline_runner._run_classification` li inizializza a `[]`), quindi il
rilevamento credenziali usa solo i segnali L1 persistiti.

### Profilo fast (`fast_profile.py`)

Trellix concede ~60s totali per l'intera risposta. Il profilo fast
dimensiona la pipeline per terminare entro ~45s:

| Fase | Budget |
|---|---|
| L0+L1 (sync, locali) | ~1s |
| L2+L3 (rete, in parallelo) | ≤ 5s (timeout espliciti) |
| L4 BFS Playwright | `FAST_BUDGET = Budget(max_depth=3, max_nodes=8, timeout_s=25)` |
| L5 (prefilter/fallback) | ~1s |

Altri parametri del profilo:
- `FAST_TOP_N_ACTIONS = 1` — un solo candidato click per stato (default: 3)
- `FAST_CAPTCHA_WAIT_S = 4` — metà dell'attesa standard (default: 8)
- `FAST_L2_TIMEOUT_S = 5.0`, `FAST_L3_TIMEOUT_S = 5.0` — timeout di rete
  dimezzati (default: crt.sh/RDAP 15s, DNS 5s, JARM 10s)
- `TRELLIX_RESPONSE_TIMEOUT_S = 48` — attesa massima del wrapper (12s di
  margine sulla deadline di 60s)

La classificazione Foundry NON rientra nella garanzia di tempo: se
configurata può sforare la finestra → il wrapper risponde onestamente
"Analysis-Incomplete" e il task continua in background.

Per supportare il profilo fast, le funzioni L2/L3 accettano un parametro
`timeout`/`timeout_s` opzionale (backward-compatible, default invariati):

- `osint/certificate_transparency.py`: `query_crtsh(..., timeout=CRTSH_TIMEOUT)`
- `osint/rdap.py`: `query_rdap(..., timeout=RDAP_TIMEOUT)`
- `osint/dns_resolve.py`: `resolve_dns(..., timeout=_DNS_TIMEOUT)`
- `osint/analyzer.py`: `analyze(..., timeout_s=None)`
- `active/analyzer.py`: `analyze(..., timeout_s=None)` (solo JARM)
- `api/pipeline_runner.py`: `run_full_analysis(..., l2_timeout_s=None, l3_timeout_s=None, captcha_wait_s=8)`

### Allowlist/blacklist (`allowlist.py`)

Tabella SQLite `allowlist_blacklist` con matching sul **dominio
registrabile** (eTLD+1) — la stessa normalizzazione usata da L1 (typosquat)
e L2 (RDAP):

```sql
CREATE TABLE IF NOT EXISTS allowlist_blacklist (
    domain    TEXT PRIMARY KEY,
    list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
    note      TEXT,
    added_by  TEXT,
    added_at  TEXT NOT NULL
);
```

- `check_domain(domain)` → `{"list_type": ..., "note": ...}` o `None`
  (cercare `login.example.com` matcha l'entry `example.com`)
- `add_entry(domain, list_type, ...)` → `INSERT OR REPLACE` (idempotente)
- `remove_entry(domain)` → `True`/`False`

Un hit allowlist/blacklist bypassa completamente l'analisi: risposta
immediata con confidence 1.0 e signature `Whitelist-Override` /
`Blacklist-Override`.

### Architettura del package

```
graph_engine/api/
    ...
    fast_profile.py     — budget e timeout del profilo fast Trellix
    allowlist.py        — tabella allowlist/blacklist (matching eTLD+1)
    trellix_verdict.py  — VERDICT_MAP, build_signature, build_trellix_response
    routes_trellix.py   — build_trellix_router() — GET /trellix/analyze
```

### Test

I test del wrapper sono in `tests/graph_engine/test_trellix/`:

- `test_allowlist.py` — CRUD + matching su dominio esatto/sottodominio
- `test_verdict_mapping.py` — mapping ternario→binario, signature con/senza
  brand, `timed_out=True` forza sempre `safe`/`allow`
- `test_routes_trellix.py` — whitelist/cache hit bypassano
  `run_full_analysis`, timeout fire-and-continue (il task completa DOPO la
  risposta e il risultato è su SQLite), URL doppio-encodato
- `test_auth.py` — token richiesto quando configurato, assente altrimenti

## Configurazione

Tutta la configurazione dell'engine passa da **un unico modulo**:
[`graph_engine/config.py`](../graph_engine/config.py) — single source of
truth per endpoint e API key.  Nessuna lettura diretta di `os.environ` è
più permessa nei moduli.

### Come funziona

- Classe `Settings(BaseSettings)` (pydantic-settings) con `env_file=".env"`,
  `env_file_encoding="utf-8"`, `extra="ignore"` — variabili ignote non
  causano errori.
- Tutti i campi sono `Optional[str] = None`: senza alcuna configurazione
  il progetto funziona degradato esattamente come prima (provider di
  reputazione extra disabilitati, L5 con fallback euristico, endpoint
  Trellix aperto).
- I nomi di campo sono snake_case e si mappano alle variabili d'ambiente
  MAIUSCOLE: `azure_foundry_endpoint` ← `AZURE_FOUNDRY_ENDPOINT`, ecc.
- I valori stringa vengono strippati degli spazi accidentali (preserva il
  comportamento storico del classificatore Foundry, che faceva
  `os.getenv(...).strip()`).
- Istanza singleton `settings = Settings()` — tutti i moduli importano
  `from graph_engine.config import settings`.

### Variabili

| Variabile | Campo | Attiva | Note |
|---|---|---|---|
| `AZURE_FOUNDRY_ENDPOINT` | `azure_foundry_endpoint` | L5 Foundry | richiede anche `AGENT_ID` (`foundry_configured`) |
| `AZURE_FOUNDRY_AGENT_ID` | `azure_foundry_agent_id` | L5 Foundry | richiede anche `ENDPOINT` |
| `AZURE_TENANT_ID` | `azure_tenant_id` | auth Foundry (service principal) | richiede anche `CLIENT_ID` + `CLIENT_SECRET` (`service_principal_configured`) |
| `AZURE_CLIENT_ID` | `azure_client_id` | auth Foundry (service principal) | richiede anche `TENANT_ID` + `CLIENT_SECRET` |
| `AZURE_CLIENT_SECRET` | `azure_client_secret` | auth Foundry (service principal) | richiede anche `TENANT_ID` + `CLIENT_ID`; senza la terna completa → `DefaultAzureCredential` |
| `AZURE_VISION_ENDPOINT` | `azure_vision_endpoint` | arricchimento L5 (OCR + Brand Detection) | richiede anche `AZURE_VISION_KEY` (`vision_configured`); riusa la risorsa Cognitive Services già attiva (italynorth) |
| `AZURE_VISION_KEY` | `azure_vision_key` | arricchimento L5 (OCR + Brand Detection) | richiede anche `AZURE_VISION_ENDPOINT`; chiave della risorsa (header `Ocp-Apim-Subscription-Key` per la REST legacy v3.2, `AzureKeyCredential` per la SDK moderna) |
| `MISP_URL` | `misp_url` | provider MISP (L2) | richiede anche `MISP_API_KEY` (`misp_configured`) |
| `MISP_API_KEY` | `misp_api_key` | provider MISP (L2) | richiede anche `MISP_URL` |
| `OPENCTI_URL` | `opencti_url` | provider OpenCTI (L2) | richiede anche `OPENCTI_API_KEY` (`opencti_configured`) |
| `OPENCTI_API_KEY` | `opencti_api_key` | provider OpenCTI (L2) | richiede anche `OPENCTI_URL` |
| `URLHAUS_API_KEY` | `urlhaus_api_key` | provider URLhaus (L2) | campo singolo (`urlhaus_configured`); endpoint fisso `urlhaus-api.abuse.ch`, chiave gratuita da https://auth.abuse.ch/ |
| `TRELLIX_API_TOKEN` | `trellix_api_token` | auth Bearer su `/trellix/analyze` | campo singolo (`trellix_auth_required`) |

Le property `foundry_configured` / `vision_configured` / `misp_configured`
/ `opencti_configured` richiedono **ENTRAMBE** le variabili della coppia
(una sola non basta); `service_principal_configured` richiede **TUTTE e
tre** le variabili AAD; `urlhaus_configured` e `trellix_auth_required`
sono True con il singolo valore impostato (e non vuoto).

### Attivazione

Copia `.env.example` in `.env` (il `.env` vero è in `.gitignore` — MAI
committarlo) e valorizza le coppie che ti servono:

```bash
# .env
AZURE_FOUNDRY_ENDPOINT=https://<progetto>.openai.azure.com
AZURE_FOUNDRY_AGENT_ID=<agent-id>        # → L5 con Foundry invece del fallback
AZURE_TENANT_ID=<tenant-id>              # → auth Foundry via ClientSecretCredential
AZURE_CLIENT_ID=<client-id>              #   (terna completa → niente `az login`)
AZURE_CLIENT_SECRET=<secret>             #   senza terna → DefaultAzureCredential
AZURE_VISION_ENDPOINT=https://<risorsa>.cognitiveservices.azure.com  # → OCR + Brand Detection sugli screenshot
AZURE_VISION_KEY=<chiave-risorsa>        #   (risorsa Cognitive Services riusata)
MISP_URL=https://misp.example.org        # → provider MISP attivo in L2
MISP_API_KEY=<api-key>
OPENCTI_URL=https://opencti.example.org  # → provider OpenCTI attivo in L2
OPENCTI_API_KEY=<api-key>
URLHAUS_API_KEY=<auth-key>               # → provider URLhaus attivo in L2 (gratuita, https://auth.abuse.ch/)
TRELLIX_API_TOKEN=<token>                # → /trellix/analyze richiede Bearer
```

### Aggiungere un futuro provider a chiave

Pattern da seguire (documentato anche in `.env.example`):

1. Aggiungere il campo tipizzato in `graph_engine/config.py` (e, se serve
   una coppia URL+key, la property `*_configured`).
2. Leggere il valore nel provider via `from graph_engine.config import
   settings` — mai `os.environ.get(...)` diretto.
3. Documentare la variabile in `.env.example`.
4. Aggiornare la tabella sopra.
