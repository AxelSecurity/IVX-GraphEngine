"""Deterministic pre-filter — cheap, honest, deliberately limited.

This filter runs BEFORE the Foundry Agent call.  It returns a Verdict
in exactly two situations:

1. **MISP to_ids hit** — the URL (or its hostname/domain/IP) appears
   in a MISP feed with ``to_ids=true``: an analyst-curated, IDS-grade
   IOC (e.g. CERT-AGID feeds).  That is a verified malicious signal,
   so the filter decides ``phishing`` at high confidence WITHOUT
   consulting the model.  Rationale: a decoy/error landing page must
   never outweigh a curated IOC (2026-08-27: s.kemkes.go.id/ejuiaer
   short-link — MISP/CERT-AGID had 4 phishing events with
   to_ids=true, but Foundry judged the broken error page "benign"
   because L4 saw no credential fields).
2. **Trivially inconclusive L4** — the bundle is so sparse that no
   model could make a reliable judgment → ``suspicious`` at minimal
   confidence.

In all other cases it returns None, delegating to the full classifier.

DESIGN NOTE — why the rest of the filter stays deliberately weak:
    Apart from the MISP-to_ids rule above, the pre-filter only catches
    the trivially inconclusive case of "we barely explored anything"
    (sparse L4).  It does NOT intercept when L1/L2/L3 have already
    produced real signal — lexical/passive risk scores above threshold
    or strong evidence keys — because there the signal exists and is
    merely un-aggregated, which is exactly the classifier's job.
    Intercepting there would burn real cases to save model calls
    (2026-08: a live phishing domain with a high passive_risk_score
    was short-circuited as "insufficient data" because L4 had visited
    a single, text-less state).
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


# ---------------------------------------------------------------------------
# MISP to_ids rule (verified malicious signal — decides WITHOUT the model)
# ---------------------------------------------------------------------------
# A ``reputation_hit`` Evidence carries the provider's ``details`` dict in
# ``bundle["strong_evidence_details"]["reputation_hit"]``.  Only MISP
# produces ``to_ids_match=True`` (URLhaus/OpenCTI have no such field), so
# its presence identifies the MISP feed unambiguously.
#
# to_ids=true in MISP means the IOC is published FOR intrusion-detection
# systems — attributes flagged this way are curated by human analysts
# (CERT-AGID feeds carry them with tags like ``campaign-type:phishing``).
# Per user decision (2026-08-27): a MISP to_ids hit means the URL is
# malicious, full stop — the verdict must not depend on the model, and
# a decoy/error landing page must not dilute it.

# Confidence modulation: a match on the full URL or hostname is the
# strongest possible signal; a match limited to the registrable domain
# or an IP still identifies malicious infrastructure, but slightly less
# precisely (shared hosting is possible).
_MISP_IDS_URL_CONFIDENCE = 0.95      # matched_types include url/hostname
_MISP_IDS_INFRA_CONFIDENCE = 0.85    # match only on domain/ip-dst

# Tag prefixes that carry threat-intel semantics (kept in the rationale);
# transport/administrative tags like ``tlp:*`` are filtered out.
_TAG_PREFIXES_KEPT = (
    "CERT-",
    "campaign-type:",
    "phishing-name:",
    "country-target:",
    "attack-method:",
    "theme:",
    "via:",
)

_MAX_RATIONALE_TAGS = 8


def _misp_to_ids_details(bundle: dict) -> Optional[dict]:
    """Return the details of a MISP ``reputation_hit`` with to_ids=true.

    Returns None when no such evidence exists (no MISP feed configured,
    only ``to_ids=false`` context matches, or a non-MISP provider hit).

    Robusto alla serializzazione: il bundle costruito da
    ``build_evidence_bundle`` coerce già il valore a dict, ma per una
    regola di sicurezza il valore stringa (JSON) viene coerd anche qui —
    la decisione "malevolo su IOC verificato" non deve mai saltare per
    un dettaglio di serializzazione.
    """
    from graph_engine.classifier.evidence_bundle import _coerce_evidence_value

    for rep in bundle.get("strong_evidence_details", {}).get(
        "reputation_hit", []
    ):
        rep = _coerce_evidence_value(rep)
        if isinstance(rep, dict) and rep.get("to_ids_match") is True:
            return rep
    return None


def _misp_verdict(bundle: dict, hit: dict) -> Verdict:
    """Build the deterministic phishing Verdict from a MISP to_ids hit."""
    matched_types = set(hit.get("matched_types") or [])
    if {"url", "hostname"} & matched_types:
        confidence = _MISP_IDS_URL_CONFIDENCE
    else:
        confidence = _MISP_IDS_INFRA_CONFIDENCE

    # I tag ``phishing-name:*`` del feed identificano il brand impersonato
    brands = sorted({
        tag.split(":", 1)[1].strip()
        for tag in hit.get("tags") or []
        if isinstance(tag, str)
        and tag.startswith("phishing-name:")
        and len(tag.split(":", 1)) == 2
    })
    brand = ", ".join(brands) or None

    info_tags = [
        tag for tag in hit.get("tags") or []
        if isinstance(tag, str) and tag.startswith(_TAG_PREFIXES_KEPT)
    ]
    tag_str = ", ".join(info_tags[:_MAX_RATIONALE_TAGS])

    match_count = hit.get("match_count", "?")
    event_count = hit.get("event_count", "?")
    types_str = ", ".join(sorted(matched_types))

    return Verdict(
        target_id=bundle.get("target_id", ""),
        classification=Classification.phishing,
        confidence=confidence,
        produced_by="prefilter",
        brand=brand,
        kit_family=None,
        rationale=(
            "Hit MISP con to_ids=true: l'URL o la sua infrastruttura è "
            "presente in un feed di minacce curato manualmente dagli "
            f"analisti (IOC per IDS). Dettagli: {match_count} attributi "
            f"({types_str}) in {event_count} eventi."
            + (f" Tag: {tag_str}." if tag_str else "")
            + " Feed verificato → classificato malevolo senza consultare "
            "il classificatore AI."
        ),
        final_url=bundle.get("canonical_url") or bundle.get("input_url"),
        exfil_endpoint=None,
    )


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
    """Return a deterministic Verdict, or None to delegate to Foundry.

    Cases intercepted (return non-None):

    0. MISP ``reputation_hit`` with ``to_ids_match=True`` — verified
       analyst-curated IOC → ``phishing`` at high confidence.  This
       rule runs FIRST and overrides everything else, including the
       strong-signal delegation below: a decoy landing page must not
       outvote a curated IDS feed (2026-08-27 kemkes case).

    Then, only when NO layer produced signal:

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

    # ── Rule 0: MISP to_ids hit → verified malicious, decide now ────────
    # Priority over the strong-signal delegation: a decoy/error landing
    # page must never outweigh a curated IDS-grade IOC (see module
    # docstring for the 2026-08-27 false-negative case).
    misp_hit = _misp_to_ids_details(bundle)
    if misp_hit is not None:
        return _misp_verdict(bundle, misp_hit)

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
