"""Profilo "fast" per il wrapper sincrono compatibile Trellix.

Il limite di 60s è imposto da Azure Front Door davanti a Trellix
(policy aziendale, NON modificabile) — il wrapper attende al massimo
TRELLIX_RESPONSE_TIMEOUT_S (56s) per lasciare margine di costruzione/
serializzazione della risposta.  Il budget qui sotto è dimensionato
perché la pipeline L0→L5 termini entro la finestra:

    L0+L1 (sync, locali)          ~1s
    L2+L3 (rete, in parallelo)    ≤ 5s  (timeout espliciti)
    L4  (BFS Playwright)          ≤ 25s (FAST_BUDGET.timeout_s, settle
                                         ridotto e page timeout 15s;
                                         screenshot full_page per stato
                                         incluso — gli artefatti sono
                                         attivi: senza di essi il
                                         modello non "vede" la pagina)
    L5  (bundle + Vision sui
         leaf, in parallelo)      ~3-5s (OCR + Brand Detection)
    L5  (prefilter/fallback)      ~1s
                                ------
                                 ~36-42s < 56s (attesa del wrapper)
                                 < 60s (deadline Front Door)

La classificazione Foundry NON rientra nella garanzia: se configurata
può sforare la finestra → il wrapper risponde "Analysis-Incomplete"
onestamente e il task continua in background (in un worker thread,
senza mai congelare il loop dell'API).
"""

from __future__ import annotations

from graph_engine.budget import Budget

# ── Budget esplorazione browser ────────────────────────────────────────────
# Profilo ridotto rispetto ai default (max_depth=6, max_nodes=40,
# timeout_s=180) perché Trellix concede ~60s totali per l'intera risposta.
# Dopo overhead (ingest L0, lexical L1, OSINT/active L2+L3, serializzazione
# HTTP), restano ~25-30s per il browser Playwright (L4).
#
# NON usato da CLI (`python -m graph_engine.cli`) o dashboard — quelli
# vogliono l'esplorazione completa.
FAST_BUDGET = Budget(max_depth=3, max_nodes=8, timeout_s=25)

# ── Azioni per stato ──────────────────────────────────────────────────────
# Un solo candidato click per stato invece dei 3 default: meno rami da
# esplorare → meno pagine da caricare → si resta nel budget.
FAST_TOP_N_ACTIONS = 1

# ── Attesa CAPTCHA ────────────────────────────────────────────────────────
# Metà dell'attesa standard (8s).  I gate CAPTCHA richiedono interazione
# umana reale; 4s bastano per rilevare il blocco senza sprecare budget.
# Con captcha_wait_s <= 4 l'explorer usa anche il settle gate ridotto
# (_GATE_SETTLE_FAST_S = 1.5s invece di 3.0s).
FAST_CAPTCHA_WAIT_S = 4

# ── Timeout di rete L2/L3 ─────────────────────────────────────────────────
# Default: CTLOGS=15s, RDAP=15s, DNS=5s, JARM=10s.
# Nel fast path li dimezziamo: se un provider non risponde in 5-8s,
# probabilmente è inaccessibile o il target è già sospetto.
# timeout_s fa anche da ceiling al client HTTP condiviso di L2 e L3
# (redirect_chain, favicon): nel fast ogni richiesta è cappata a 5s
# invece dei 30s di default.  Floor residuo: differential_fetch usa un
# client proprio a 15s per profilo (i profili girano in parallelo).
FAST_L2_TIMEOUT_S = 5.0
FAST_L3_TIMEOUT_S = 5.0

# ── Settle post-navigazione (L4) ──────────────────────────────────────────
# Default: 4.0s per stato.  Il fast lo riduce a 3.0s — resta sopra il
# floor di ~2.5s del polling adattivo (il redirect JS ritardato a 2s dei
# kit TDS reali continua a essere catturato).
FAST_SETTLE_MAX_WAIT_S = 3.0

# ── Timeout di navigazione Playwright (L4) ────────────────────────────────
# Default: 30000ms per goto.  Il fast lo dimezza: un target lento che non
# risponde in 15s è di per sé un segnale, non vale la pena aspettarlo.
FAST_PAGE_TIMEOUT_MS = 15000

# ── Timeout attesa wrapper ────────────────────────────────────────────────
# L'attesa massima del wrapper Trellix per il completamento del task.
#
# Il limite di 60s è imposto da Azure Front Door davanti a Trellix:
# fisso per policy aziendale, NON modificabile.  56s lascia 4s di
# margine reale per costruzione/serializzazione della risposta e
# variabilità di rete.
#
# La chiamata Foundry NON ha un tetto proprio (decisione esplicita: è
# il cuore della classificazione, non va troncata artificialmente) —
# la protezione resta solo quella del wrapper esterno (asyncio.wait
# con questo timeout in routes_trellix.py), come già oggi.
TRELLIX_RESPONSE_TIMEOUT_S = 56
