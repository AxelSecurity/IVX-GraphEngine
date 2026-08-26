"""Deterministic pre-filter — cheap, honest, deliberately limited.

This filter runs BEFORE the Foundry Agent call.  It returns a Verdict
ONLY when the evidence bundle is so sparse that no model could make a
reliable judgment.  In all other cases it returns None, delegating to
the full classifier.

DESIGN NOTE — why this is deliberately weak:
    The pre-filter only catches the trivially inconclusive case of
    "we barely explored anything" (sparse L4).  It does NOT intercept
    when L1/L2/L3 have already produced real signal — lexical/passive
    risk scores above threshold or strong evidence keys — because there
    the signal exists and is merely un-aggregated, which is exactly the
    classifier's job.  Intercepting there would burn real cases to save
    model calls (2026-08: a live phishing domain with a high
    passive_risk_score was short-circuited as "insufficient data"
    because L4 had visited a single, text-less state).
"""

from __future__ import annotations

from typing import Optional

from graph_engine.models import Classification, Verdict

# ---------------------------------------------------------------------------
# Strong-signal rules (L1/L2/L3)
# ---------------------------------------------------------------------------

# Threshold on the L1/L2 risk scores above which the prefilter must NOT
# intercept.  Both scores are weighted sums clamped to 0-1; 0.5 means at
# least one heavy signal (or several medium ones) was observed — enough
# material for the model even if L4 barely explored.  Below this the
# score alone doesn't prove the case is classifiable.
_RISK_SCORE_SIGNAL_THRESHOLD = 0.5


def _has_strong_signal(bundle: dict) -> bool:
    """True when L1/L2/L3 evidence alone already carries enough signal.

    Checked BEFORE the "insufficient data" cases: a sparse L4 exploration
    is NOT trivially inconclusive when other layers produced real signal.
    """
    lexical = bundle.get("lexical_risk_score")
    passive = bundle.get("passive_risk_score")
    if lexical is not None and lexical >= _RISK_SCORE_SIGNAL_THRESHOLD:
        return True
    if passive is not None and passive >= _RISK_SCORE_SIGNAL_THRESHOLD:
        return True

    # Strong evidence keys: presence alone is a signal.
    summary = bundle.get("evidence_summary", {})
    if summary.get("cloaking_detected") or summary.get("reputation_hit"):
        return True

    # Typosquat is strong only at edit distance 1 (D2 is a weak hint),
    # so it needs the value, not just the key.
    for detail in bundle.get("strong_evidence_details", {}).get("typosquat", []):
        if isinstance(detail, dict) and detail.get("distance") == 1:
            return True

    return False


def prefilter(bundle: dict) -> Optional[Verdict]:
    """Return a Verdict for trivially insufficient data, or None.

    Cases intercepted (return non-None) — only when NO layer produced
    signal:
    1. Only 1 state AND no visible text was extracted from it
       → exploration didn't get anywhere useful.
    2. ``had_unhandled_error`` is True AND no other signals
       (no gate, no form fields, no navigation errors, no redirects)
       → the exploration simply failed; we can't classify.

    NOT intercepted (return None → delegate to Foundry):
    - L1/L2 risk score above ``_RISK_SCORE_SIGNAL_THRESHOLD``;
    - strong evidence keys present (cloaking_detected, reputation_hit,
      typosquat at distance 1);
    - anything with real L4 content.
    """

    # L1/L2/L3 signal takes precedence over L4 sparsity: when other
    # layers already produced real signal, do NOT intercept — the model
    # has enough to judge, we just haven't aggregated it yet.
    if _has_strong_signal(bundle):
        return None

    flags = bundle.get("flags", {})
    graph_states = bundle.get("states", [])
    num_states = bundle.get("num_states", 0)
    transition_kinds = bundle.get("transition_kinds_seen", {})

    # Extract all visible text from every graph state: DOM text AND OCR
    # text from screenshots.  Una pagina che rende testo solo via
    # canvas/immagini ha visible_text vuoto ma ocr_text non vuoto — NON
    # è "nessun testo visibile" (il DOM da solo non basta più a
    # giudicare la sparsità).
    all_visible_text = " ".join(
        (st.get("visible_text", "") or "")
        + " "
        + (st.get("ocr_text", "") or "")
        for st in graph_states
    ).strip()

    # Count total form fields
    total_fields = sum(
        len(st.get("form_fields", [])) for st in graph_states
    )

    # ---- Case 1: single state, no visible content -----------------------
    if num_states <= 1 and not all_visible_text:
        return Verdict(
            target_id=bundle.get("target_id", ""),
            classification=Classification.suspicious,
            confidence=0.05,
            produced_by="prefilter",
            rationale=(
                "Explorazione inconclusiva: è stato visitato solo il "
                "root state e non è stato possibile estrarre testo "
                "visibile dalla pagina. Dati insufficienti per un "
                "giudizio affidabile."
            ),
        )

    # ---- Case 2: unhandled error with no other signals ------------------
    if flags.get("had_unhandled_error") and (
        not flags.get("had_gate")
        and total_fields == 0
        and not flags.get("had_navigation_error")
        and len(transition_kinds) <= 1
    ):
        return Verdict(
            target_id=bundle.get("target_id", ""),
            classification=Classification.suspicious,
            confidence=0.05,
            produced_by="prefilter",
            rationale=(
                "Esplorazione inconclusiva: un errore non gestito ha "
                "interrotto l'esplorazione e non sono stati raccolti "
                "segnali sufficienti (nessun gate, nessun form field, "
                "nessun redirect). Dati insufficienti per un giudizio "
                "affidabile."
            ),
        )

    # ---- Normal path: delegate to Foundry -------------------------------
    return None
