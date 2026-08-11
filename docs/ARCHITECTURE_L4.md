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
   completi, mai screenshot in alta risoluzione non necessari.

### Evidence bundle (compatto)

Il bundle (`graph_engine/classifier/evidence_bundle.py`) contiene:
- Metadati dell'esplorazione: `input_url`, `canonical_url`, `num_states`,
  `num_transitions`, `max_depth_reached`
- Conteggi per tipo di transizione (`transition_kinds_seen`)
- Flag booleani da Evidence: `had_gate`, `had_navigation_error`,
  `had_replay_fallback`, `had_unhandled_error`
- Per ogni stato foglia (senza transizioni in uscita): URL, titolo pagina,
  testo visibile estratto (troncato a ~1500 caratteri, strip di
  script/style/tag), risultato di `scan_form_fields()` (sola lettura)

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
