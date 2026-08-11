# CLAUDE.md — IVX-GraphEngine

Questo file fornisce indicazioni permanenti a Claude per lavorare su questo progetto.

## Lingua

- **Rispondi SEMPRE in italiano.** Il progetto è interamente in italiano: README, documentazione, commenti nel codice, docstring. Ogni risposta, spiegazione, commit message e interazione deve essere in italiano.

## Panoramica del progetto

IVX-GraphEngine è un **esploratore dinamico di grafi di stato per l'analisi di URL di phishing**. Segue catene di redirect multi-hop (HTTP, meta-refresh, JS) e interazioni utente (click, gate CAPTCHA) fino al payload finale, modellando il percorso come un **grafo di stati esplorabile** (non una catena lineare). È un componente standalone della toolchain Horus/IntelIVX, progettato per essere integrato via HTTP/code (non import diretto).

## Setup e comandi

```bash
# Setup iniziale
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# Esecuzione CLI
python -m graph_engine.cli <url>
python -m graph_engine.cli <url> --classify                    # con classificazione L5
python -m graph_engine.cli <url> --no-artifacts                # senza salvataggio artefatti
python -m graph_engine.cli <url> --max-depth 3 --max-nodes 20 --timeout 120

# Test
pytest                                  # suite predefinita (esclude integration)
pytest -m integration                   # solo test con rete reale (httpbin.org)
pytest -v                               # verbose
```

## Architettura

### Modello di dominio (`graph_engine/models.py`)
Tutti modelli Pydantic v2 con `from __future__ import annotations`:

- **`AnalysisTarget`** — unità di lavoro: `id` (UUID), `input_url`, `canonical_url`, `url_hash`, `status` (queued/running/done/error), `root_state_id`, `created_at`
- **`State`** — nodo del grafo; dedup su `(target_id, url, dom_hash)`. Campi: `id`, `target_id`, `url`, `dom_hash`, `depth=0`, `screenshot_ref`, `har_ref`
- **`Transition`** — arco tipizzato: `id`, `target_id`, `from_state`, `to_state`, `kind` (enum sotto), `trigger` (dict opzionale), `ts`
- **`Evidence`** — segnale atomico con provenienza: `scope` (target/state/transition), `layer` (L0–L5), `key`, `value`, `weight=1.0`, `produced_by`, `ts`
- **`Verdict`** — esito aggregato: `target_id`, `classification`, `confidence=0.0`, `produced_by` (obbligatorio: `"foundry"` | `"prefilter"` | `"heuristic_fallback"`), `brand`, `kit_family`, `rationale`, `final_url`, `exfil_endpoint`

### Enum

- **`TransitionKind`** (9 valori): `http_3xx`, `meta_refresh`, `js_location`, `history_push`, `click`, `form_submit` (mantenuto per retrocompatibilità, **non più prodotto**), `new_tab`, `gate_solved`, `ws_message`
- **`TargetStatus`**: `queued`, `running`, `done`, `error`
- **`EvidenceScope`**: `target`, `state`, `transition`
- **`Classification`**: `benign`, `suspicious`, `phishing` — **NON esiste `aitm`** (la classificazione riguarda *cosa* è il sito, non *come* esfiltra; la tecnica va in `kit_family`/`rationale`)

### Package `graph_engine/`

| Modulo | Righe | Responsabilità |
|---|---|---|
| `models.py` | 136 | Modelli Pydantic v2 + 4 enum |
| `budget.py` | 20 | `Budget` dataclass: `max_depth=6`, `max_nodes=40`, `timeout_s=180` |
| `dom_hash.py` | 132 | Normalizzazione DOM + SHA-256 via lxml; rimuove nonce/CSRF/timestamp/UUID/hash, ordina attributi, elimina `value` da elementi con segnale effimero |
| `actions.py` | 212 | Scoring elementi interagibili: `ActionCandidate` + `enumerate_actionable(page)` con script JS inlinato (keyword match W=0.50, salienza visiva 0.30, posizione 0.20); ~30 keyword; selettori `#id`, `tag:has-text(...)`, o tag+classe |
| `gate_solver.py` | 116 | `detect_captcha(page)` (riconoscimento iframe: cloudflare_turnstile/hcaptcha/recaptcha) + `try_pass_gate(page, wait_seconds=8)` — attesa auto-risoluzione, singolo click checkbox, mai puzzle reali |
| `explorer.py` | 1079 | `StateGraphExplorer` — il motore BFS principale (vedi sotto) |
| `cli.py` | 251 | CLI argparse: `python -m graph_engine.cli <url> [opzioni]` |
| `classifier/__init__.py` | 1 | Marker: "L5 — Classification layer" |
| `classifier/form_inventory.py` | 110 | `scan_form_fields(page)` — scansione passiva sola lettura via JS; enumera `{tag, type, name_or_id, nearby_label_text}` per input/select/textarea visibili; esclude hidden/submit/button/checkbox/radio/file |
| `classifier/evidence_bundle.py` | 156 | `build_evidence_bundle(...)` — dict semplice (NON Pydantic); `bundle_to_prompt_text(bundle)` — sezioni testuali etichettate, deliberatamente non JSON |
| `classifier/prefilter.py` | 88 | `prefilter(bundle)` → Verdict o None; intercetta solo casi banalmente inconclusivi; restituisce `suspicious` conf 0.05, `produced_by="prefilter"` |
| `classifier/foundry_classifier.py` | 303 | `classify(bundle, screenshot_paths)` → Verdict; richiede env `AZURE_FOUNDRY_ENDPOINT` e `AZURE_FOUNDRY_AGENT_ID`; fallback `_heuristic_fallback` se non configurato |
| `classifier/system_prompt.txt` | 55 | System prompt per l'agente Foundry |

### `StateGraphExplorer` (explorer.py) — meccanismi chiave

- **`_INIT_SCRIPT`**: iniettato in ogni pagina; sovrascrive `location.assign`/`location.replace`/`window.open` per *registrare* le navigazioni JS nello stash `__ge_js_locations` invece di eseguirle
- **`_install_navigation_guard`**: `page.route("**/*")` intercetta e abortisce le navigazioni iniziate dalla pagina (le registra come candidate `js_location`), tranne quando `_our_goto_active` (nostro goto) o `_replaying`
- **`_navigate_and_create_state`**: goto → 1.5s settle → legge intercettazioni JS → percorre catena `redirected_from` per 3xx → cattura HTML/hash → salva artefatti
- **`_replay_to_state`**: per esplorare uno stato raggiunto via click/SPA, ripercorre l'intero percorso di transizioni (root goto → gate re-solve → click) con flag `_replaying` attivo per sopprimere side-effect. In caso di fallimento, fallback a `goto(state.url)`, registra evidenza `replay_fallback_used`, lo stato è trattato come foglia
- **`_execute_click_action`**: pagina fresca per click, replay path, confronto `dom_hash` pre/post + URL; nessun cambiamento → ramo scartato; stato post con depth+1
- **Contenimento errori**: il loop BFS wrappa ogni stato in try/except → evidenza `unhandled_node_error`; un singolo fallimento non crasha l'esplorazione
- **Cattura artefatti**: `_save_artifacts` scrive `data/graph_artifacts/<target_id>/<state_id>/` con `screenshot.png` (full_page), `dom.html`, `snapshot.har` (HAR 1.2 minimale costruito da listener request/response)
- **Evidenze prodotte**: `navigation_error`, `replay_fallback_used`, `unhandled_node_error`, `blocked_by_gate`, `Artifact error — ...`

### Pipeline L5 a due stadi

1. **`prefilter()`** — deterministico, deliberatamente debole (L1/L2 non ancora implementati): intercetta solo "1 stato + nessun testo visibile" e "errore non gestito + nessun altro segnale"
2. **`classify()`** → Foundry Agent (Azure AI Projects SDK) — solo se il prefilter restituisce None

## Vincoli NON NEGOZIABILI

Questi vincoli non devono mai essere violati. Se una modifica li contraddice, va bloccata.

1. **Classificazione Foundry stateless**: ogni chiamata `classify()` crea un **nuovo** thread e lo cancella dopo l'uso. I thread ID non vengono MAI riutilizzati tra analisi. Questo vincolo esiste perché un bug storico (2026-08) causava falsi positivi: la memoria conversazionale di Foundry faceva "ricordare" campi credential di un caso phishing precedente durante l'analisi di un URL benigno. La funzione `_new_thread_id(client)` è estratta come separata proprio per permettere ai test di verificare questo vincolo. Vedi `docs/ARCHITECTURE.md § L5 — Classificazione`.

2. **Nessuna injection di credenziali**: la funzionalità è stata completamente rimossa (2026-08-09). File eliminati: `credential_injection.py`, `canary_identity.py` e relativi test. Rimosse ~155 righe da `explorer.py` (`_handle_credential_submit`, ramo `form_submit`). Il progetto classifica passivamente — non riempie né invia mai form. I test verificano l'assenza di chiavi evidenza come `canary_email_submit_endpoint`, `otp_stage_reached`, ecc.

3. **Niente `aitm` nella Classification**: l'enum `Classification` ha solo `benign`, `suspicious`, `phishing`. La tecnica di esfiltrazione (AITM, reverse proxy, ecc.) va documentata in `kit_family`/`rationale`, non nella classificazione.

4. **Scansione form passiva**: `scan_form_fields()` è sola lettura — zero mutazioni DOM. Non viene mai iniettato né rimosso nulla dalla pagina.

5. **`produced_by` obbligatorio**: ogni `Verdict` DEVE avere `produced_by` valorizzato (`"foundry"`, `"prefilter"` o `"heuristic_fallback"`). I consumatori a valle devono poter distinguere un giudizio AI da un fallback deterministico.

6. **Contenimento errori**: un nodo che fallisce non deve MAI crashare l'intera esplorazione. Si registra evidenza e si continua.

## Convenzioni di testing

- **`asyncio_mode = auto`** in `pytest.ini` → i test async NON hanno bisogno del decoratore `@pytest.mark.asyncio`
- **`addopts = -m "not integration"`** → i test con `@pytest.mark.integration` sono esclusi dalla suite predefinita. Si eseguono con `pytest -m integration`
- **Schema dei test**: mirror di `graph_engine/` sotto `tests/graph_engine/`; `tests/conftest.py` è un placeholder
- **HTTP server locali**: `HTTPServer` su `127.0.0.1` porta random in thread separato per test che richiedono rete locale (NON marcati integration)
- **Browser Playwright reali**: `page.set_content()` per test DOM-level; MAI rete reale in questi test
- **Mock e patch**: `AsyncMock`/`MagicMock` per Playwright; `patch.object` per isolare funzioni specifiche; `patch.dict("os.environ", {}, clear=True)` per testare fallback
- **Test Foundry**: TUTTE le chiamate Azure sono mockate; il test `test_thread_created_fresh_for_each_classify_call` verifica che `_new_thread_id` produca ID distinti e che quegli ID siano effettivamente passati a valle (non ignorati)
- I test NON devono mai fare chiamate reali a servizi Azure

## Dipendenze

```
playwright>=1.60.0
pydantic>=2.7.0
pydantic-settings>=2.2.0
lxml>=5.1.0
pytest
pytest-asyncio
azure-ai-projects>=0.1.0   # opzionale — solo per --classify
azure-identity>=1.16.0     # opzionale — solo per --classify
```

- **Python 3.9.6** (venv di sistema macOS CommandLineTools). `from __future__ import annotations` è usato ovunque; `asyncio.Queue[int]` funziona su 3.9.
- **Non esiste `pyproject.toml`** — per aggiungere dipendenze si modifica `requirements.txt`
- I moduli Azure NON sono installati nel venv; il classificatore degrada a fallback euristico senza

## Variabili d'ambiente

Solo per `--classify`:
- `AZURE_FOUNDRY_ENDPOINT` — endpoint del progetto Azure AI Foundry
- `AZURE_FOUNDRY_AGENT_ID` — ID dell'agente Foundry configurato

`.env` è in `.gitignore`. Nessuna credenziale viene mai hardcodata o committata.

## Note aggiuntive

- Il progetto non ha remote git configurato; branch `main`, ~22 commit
- `data/graph_artifacts/` è gitignorato — sono artefatti di runtime locali
- La persistenza SQLite (aiosqlite) è pianificata ma non ancora implementata
- I layer L1 (reputazione dominio, TLD risk) e L2 (blacklist, certificate transparency) sono lavori futuri che rafforzeranno il prefilter
- Evidenze di errore prodotte dall'explorer hanno `produced_by="StateGraphExplorer"`
- L'integrazione con IntelIVX avviene via HTTP/code, MAI tramite import diretto
