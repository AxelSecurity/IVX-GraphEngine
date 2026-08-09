# L4 — Dynamic State-Graph Engine — Architettura di riferimento

## Contesto

Le URL di phishing moderne raggiungono il payload finale solo dopo catene di redirect
eterogenee (HTTP, meta-refresh, JavaScript) e, nei kit AiTM, dopo interazioni utente reali
(inserimento email, password). Il motore modella questo percorso come **grafo di stati
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
  (benign|suspicious|phishing|aitm)`, `confidence`, `brand`, `kit_family`, `rationale`,
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

## Interaction engine (fasi successive, non in questo primo batch)

- **Actionable scoring**: elementi interagibili (`button, a, [role=button],
  input[type=submit]`) ordinati per punteggio = keyword d'azione (verify, continue, sign in,
  unlock, view document, proceed, open) + salienza visiva (dimensione/posizione bounding box)
  + posizione nel DOM. Click in ordine di punteggio, attesa navigazione/mutazione, ricorsione.
- **Gate solver**: rilevamento e gestione di challenge anti-bot (Turnstile/hCaptcha
  interattivo, banner cookie, splash "click to continue"). Non prevede bypass crittografico di
  CAPTCHA, solo navigazione di gate standard.
- **Credential injection con canary**: identità sintetica (mai reale). Compilazione email →
  submit → osservazione endpoint POST (candidato exfil). Poi password → submit → osservazione
  relay MFA. Safety non negoziabile: solo credenziali canary, container effimero, egress
  isolato, nessun dato reale mai inviato.

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
