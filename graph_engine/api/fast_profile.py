"""Profilo "fast" per il wrapper sincrono compatibile Trellix.

Trellix attende una risposta entro ~60 secondi. Il budget qui sotto
è dimensionato perché la pipeline L0→L5 termini entro ~45s:

    L0+L1 (sync, locali)          ~1s
    L2+L3 (rete, in parallelo)    ≤ 5s  (timeout espliciti)
    L4  (BFS Playwright)          ≤ 30s (FAST_BUDGET.timeout_s)
    L5  (prefilter/fallback)      ~1s
                                ------
                                 ~37s < 48s (attesa del wrapper)
                                 < 60s (deadline Trellix)

La classificazione Foundry NON rientra nella garanzia: se configurata
può sforare la finestra → il wrapper risponde "Analysis-Incomplete"
onestamente e il task continua in background.
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
FAST_CAPTCHA_WAIT_S = 4

# ── Timeout di rete L2/L3 ─────────────────────────────────────────────────
# Default: CRTSH=15s, RDAP=15s, DNS=5s, JARM=10s.
# Nel fast path li dimezziamo: se un provider non risponde in 5-8s,
# probabilmente è inaccessibile o il target è già sospetto.
# Le altre sonde L3 (redirect_chain, favicon, differential_fetch)
# mantengono i propri timeout interni.
FAST_L2_TIMEOUT_S = 5.0
FAST_L3_TIMEOUT_S = 5.0

# ── Timeout attesa wrapper ────────────────────────────────────────────────
# L'attesa massima del wrapper Trellix per il completamento del task.
# 12s di margine sulla deadline di 60s di Trellix.
TRELLIX_RESPONSE_TIMEOUT_S = 48
