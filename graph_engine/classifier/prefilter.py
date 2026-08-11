"""Deterministic pre-filter — cheap, honest, deliberately limited.

This filter runs BEFORE the Foundry Agent call.  It returns a Verdict
ONLY when the evidence bundle is so sparse that no model could make a
reliable judgment.  In all other cases it returns None, delegating to
the full classifier.

DESIGN NOTE — why this is deliberately weak right now:
    L1 (domain reputation, registrant age, TLD risk) and L2 (blacklist
    lookups, certificate transparency, known-kit fingerprints) have not
    been built yet in this project.  When they are, the pre-filter will
    intercept many more cases — brand-new domains with known phishing
    TLDs, domains on public blocklists, etc. — without ever calling the
    model.  For now it only catches the trivially inconclusive case of
    "we barely explored anything."
"""

from __future__ import annotations

from typing import Optional

from graph_engine.models import Classification, Verdict


def prefilter(bundle: dict) -> Optional[Verdict]:
    """Return a Verdict for trivially insufficient data, or None.

    Cases intercepted (return non-None):
    1. Only 1 state AND no visible text was extracted from it
       → exploration didn't get anywhere useful.
    2. ``had_unhandled_error`` is True AND no other signals
       (no gate, no form fields, no navigation errors, no redirects)
       → the exploration simply failed; we can't classify.
    """

    flags = bundle.get("flags", {})
    leaves = bundle.get("leaf_states", [])
    num_states = bundle.get("num_states", 0)
    transition_kinds = bundle.get("transition_kinds_seen", {})

    # Extract all visible text from leaves
    all_visible_text = " ".join(
        leaf.get("visible_text", "") for leaf in leaves
    ).strip()

    # Count total form fields
    total_fields = sum(
        len(leaf.get("form_fields", [])) for leaf in leaves
    )

    # ---- Case 1: single state, no visible content -----------------------
    if num_states <= 1 and not all_visible_text:
        return Verdict(
            target_id=bundle.get("target_id", ""),
            classification=Classification.suspicious,
            confidence=0.05,
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
