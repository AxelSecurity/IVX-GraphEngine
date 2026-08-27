"""Tests for deterministic prefilter.

Due famiglie di intercettazioni:
1. MISP ``reputation_hit`` con ``to_ids_match=True`` → phishing deterministico
   (IOC curato dagli analisti: decide SENZA il modello).
2. Casi banalmente inconclusivi (L4 sparsa e nessun segnale) → suspicious
   a confidenza minima.
"""

from __future__ import annotations

import uuid

import pytest

from graph_engine.classifier.prefilter import prefilter
from graph_engine.models import Classification


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _sparse_l4_bundle(**overrides) -> dict:
    """Bundle con L4 "vuoto": 1 stato, nessun testo visibile, nessun
    errore — il caso che il prefilter intercetterebbe come "dati
    insufficienti" guardando SOLO L4."""
    bundle = {
        "target_id": str(uuid.uuid4()),
        "input_url": "https://example.com",
        "num_states": 1,
        "num_transitions": 0,
        "max_depth_reached": 0,
        "transition_kinds_seen": {},
        "flags": {
            "had_gate": False,
            "had_navigation_error": False,
            "had_replay_fallback": False,
            "had_unhandled_error": False,
        },
        "evidence_summary": {},
        "states": [
            {
                "state_id": str(uuid.uuid4()),
                "url": "https://example.com",
                "depth": 0,
                "title": "",
                "visible_text": "",
                "form_fields": [],
            }
        ],
    }
    bundle.update(overrides)
    return bundle


class TestPrefilterReturnsVerdict:
    """prefilter returns a Verdict when data is trivially insufficient."""

    def test_single_state_no_visible_text(self):
        """1 state, no visible text → suspicious with low confidence."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 1,
            "num_transitions": 0,
            "max_depth_reached": 0,
            "transition_kinds_seen": {},
            "flags": {
                "had_gate": False,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": False,
            },
            "evidence_summary": {},
            "states": [
                {
                    "state_id": str(uuid.uuid4()),
                    "url": "https://example.com",
                    "depth": 0,
                    "title": "",
                    "visible_text": "",
                    "form_fields": [],
                }
            ],
        }

        verdict = prefilter(bundle)
        assert verdict is not None, "Should return Verdict for insufficient data"
        assert verdict.classification == Classification.suspicious
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence <= 0.1, (
            f"Confidence should be very low, got {verdict.confidence}"
        )
        assert "insufficient" in verdict.rationale.lower() or \
               "inconclusiva" in verdict.rationale.lower()

    def test_unhandled_error_no_other_signals(self):
        """Had unhandled error, no gate/fields/redirects → insufficient."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 1,
            "num_transitions": 0,
            "max_depth_reached": 0,
            "transition_kinds_seen": {},
            "flags": {
                "had_gate": False,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": True,
            },
            "evidence_summary": {"unhandled_node_error": 1},
            "states": [
                {
                    "state_id": str(uuid.uuid4()),
                    "url": "https://example.com",
                    "depth": 0,
                    "title": "",
                    "visible_text": "",
                    "form_fields": [],
                }
            ],
        }

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.suspicious
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence <= 0.1

    def test_unhandled_error_with_gate_bypasses_prefilter(self):
        """Had unhandled error BUT also had a gate → may still be phishing."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 2,
            "num_transitions": 1,
            "max_depth_reached": 1,
            "transition_kinds_seen": {"gate_solved": 1},
            "flags": {
                "had_gate": True,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": True,
            },
            "evidence_summary": {
                "unhandled_node_error": 1,
                "blocked_by_gate": 1,
            },
            "states": [],
        }

        verdict = prefilter(bundle)
        assert verdict is None, (
            "Should delegate to model — gate presence is a signal"
        )


class TestPrefilterReturnsNone:
    """prefilter returns None when there is enough data for the model."""

    def test_multi_state_with_text(self):
        """Multiple states and visible text → delegate to Foundry."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 3,
            "num_transitions": 2,
            "max_depth_reached": 2,
            "transition_kinds_seen": {"click": 2},
            "flags": {
                "had_gate": False,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": False,
            },
            "evidence_summary": {},
            "states": [
                {
                    "state_id": str(uuid.uuid4()),
                    "url": "https://example.com/final",
                    "depth": 2,
                    "title": "Login",
                    "visible_text": "Please enter your email and password",
                    "form_fields": [
                        {"tag": "input", "type": "email",
                         "name_or_id": "email",
                         "nearby_label_text": "Email"},
                        {"tag": "input", "type": "password",
                         "name_or_id": "password",
                         "nearby_label_text": "Password"},
                    ],
                }
            ],
        }

        verdict = prefilter(bundle)
        assert verdict is None, (
            "Should delegate to Foundry — data looks sufficient"
        )

    def test_single_state_with_visible_text(self):
        """Single state BUT has visible text → delegate (not clearly insufficient)."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 1,
            "num_transitions": 0,
            "max_depth_reached": 0,
            "transition_kinds_seen": {},
            "flags": {
                "had_gate": False,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": False,
            },
            "evidence_summary": {},
            "states": [
                {
                    "state_id": str(uuid.uuid4()),
                    "url": "https://example.com",
                    "depth": 0,
                    "title": "Welcome",
                    "visible_text": "This is the legitimate example.com homepage.",
                    "form_fields": [],
                }
            ],
        }

        verdict = prefilter(bundle)
        assert verdict is None, (
            "Single state WITH text should go to Foundry — "
            "the model may recognize the brand"
        )

    def test_single_state_no_dom_text_but_ocr_text(self):
        """Single state, visible_text VUOTO ma ocr_text presente (pagina
        che rende testo via canvas/immagine) → delegare a Foundry:
        l'OCR è testo visibile a tutti gli effetti."""
        bundle = _sparse_l4_bundle(
            states=[
                {
                    "state_id": str(uuid.uuid4()),
                    "url": "https://example.com/canvas-login",
                    "depth": 0,
                    "title": "",
                    "visible_text": "",
                    "ocr_text": "Accedi al tuo account Microsoft",
                    "form_fields": [],
                }
            ],
        )

        verdict = prefilter(bundle)
        assert verdict is None, (
            "OCR text is visible content: single state with OCR text "
            "must go to Foundry"
        )

    def test_empty_states_unhandled_error_no_signals(self):
        """Edge: 0 states, unhandled error → insufficient."""
        bundle = {
            "target_id": str(uuid.uuid4()),
            "input_url": "https://example.com",
            "num_states": 0,
            "num_transitions": 0,
            "max_depth_reached": 0,
            "transition_kinds_seen": {},
            "flags": {
                "had_gate": False,
                "had_navigation_error": False,
                "had_replay_fallback": False,
                "had_unhandled_error": True,
            },
            "evidence_summary": {"unhandled_node_error": 1},
            "states": [],
        }

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.suspicious
        assert verdict.produced_by == "prefilter"


class TestPrefilterStrongSignals:
    """Segnali L1/L2/L3 forti → il prefilter NON deve intercettare.

    Caso reale (2026-08): un dominio di phishing live aveva L4 ridotto a
    un solo stato senza testo visibile, MA passive_risk_score alto.
    Il prefilter guardava solo L4 e lo bollava "dati insufficienti"
    senza mai arrivare a Foundry.
    """

    def test_sparse_l4_with_high_passive_risk_score_delegates(self):
        """Caso reale di oggi: 1 stato, nessun testo, passive_risk_score
        alto → None (delega a Foundry), non un Verdict euristico."""
        bundle = _sparse_l4_bundle(passive_risk_score=0.72)

        verdict = prefilter(bundle)
        assert verdict is None, (
            "passive_risk_score alto = segnale L2 reale: il prefilter "
            "NON deve intercettare come 'dati insufficienti'"
        )

    def test_sparse_l4_with_high_lexical_risk_score_delegates(self):
        """Stesso caso con lexical_risk_score sopra soglia."""
        bundle = _sparse_l4_bundle(lexical_risk_score=0.65)

        assert prefilter(bundle) is None

    def test_sparse_l4_with_cloaking_detected_delegates(self):
        """cloaking_detected (L3) presente → c'è segnale sufficiente."""
        bundle = _sparse_l4_bundle(
            evidence_summary={"cloaking_detected": 1},
        )

        assert prefilter(bundle) is None

    def test_sparse_l4_with_reputation_hit_delegates(self):
        """reputation_hit (L2) presente → c'è segnale sufficiente."""
        bundle = _sparse_l4_bundle(
            evidence_summary={"reputation_hit": 1},
        )

        assert prefilter(bundle) is None

    def test_sparse_l4_with_typosquat_distance_1_delegates(self):
        """Typosquat a distanza 1 (L1) → segnale forte, delega."""
        bundle = _sparse_l4_bundle(
            strong_evidence_details={
                "typosquat": [
                    {"domain": "rnnovospid.cc", "brand": "Aruba",
                     "distance": 1},
                ],
            },
        )

        assert prefilter(bundle) is None

    def test_typosquat_distance_2_does_not_bypass(self):
        """Distanza 2 è un indizio debole: da sola NON basta a bypassare."""
        bundle = _sparse_l4_bundle(
            strong_evidence_details={
                "typosquat": [
                    {"domain": "rnnovospid.cc", "brand": "Aruba",
                     "distance": 2},
                ],
            },
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.produced_by == "prefilter"

    def test_score_below_threshold_still_intercepted(self):
        """Caso genuinamente vuoto: score SOTTO soglia da solo non è
        segnale → il prefilter continua a intercettare (risparmio
        chiamate preservato)."""
        bundle = _sparse_l4_bundle(passive_risk_score=0.3)

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.produced_by == "prefilter"
        assert verdict.classification == Classification.suspicious


# ---------------------------------------------------------------------------
# MISP to_ids rule — verified malicious IOC decides WITHOUT the model
# ---------------------------------------------------------------------------

# Details reali prodotti dal provider MISP (stessa forma del caso
# s.kemkes.go.id/ejuiaer del 2026-08-27: 4 eventi CERT-AGID con match
# su domain+url).
_MISP_IDS_HIT = {
    "match_count": 4,
    "matched_types": ["domain", "url"],
    "tags": [
        "CERT-AGID",
        "attack-method:linked",
        "campaign-type:phishing",
        "country-target:generic",
        "country-target:italy",
        "phishing-name:Amazon",
        "phishing-name:Netflix",
        "theme:Account sospeso",
        "theme:Aggiornamenti",
        "theme:Verifica",
        "tlp:green",
        "via:email",
    ],
    "event_count": 4,
    "to_ids_match": True,
    "context_only": False,
}


class TestMispIdsHitIntercepts:
    """Hit MISP con to_ids=true → phishing deterministico dal prefilter."""

    def test_to_ids_hit_returns_phishing_verdict(self):
        """Match su url+domain → phishing conf 0.95, brand dai tag
        phishing-name, rationale con i tag informativi (tlp:* escluso)."""
        bundle = _sparse_l4_bundle(
            canonical_url="https://s.kemkes.go.id/ejuiaer",
            passive_risk_score=0.55,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={"reputation_hit": [_MISP_IDS_HIT]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence == 0.95, (
            f"Match sull'URL completo → confidenza massima, got "
            f"{verdict.confidence}"
        )
        assert verdict.brand == "Amazon, Netflix"
        assert "to_ids=true" in verdict.rationale
        assert "campaign-type:phishing" in verdict.rationale
        assert "CERT-AGID" in verdict.rationale
        assert "tlp:green" not in verdict.rationale, (
            "I tag trasporto/amministrativi non vanno nel rationale"
        )
        assert verdict.final_url == "https://s.kemkes.go.id/ejuiaer"

    def test_infra_only_match_lower_confidence(self):
        """Match solo su domain/ip-dst (infrastruttura, non URL esatto)
        → phishing comunque, ma confidenza 0.85."""
        hit = dict(_MISP_IDS_HIT, matched_types=["domain", "ip-dst"])
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            strong_evidence_details={"reputation_hit": [hit]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence == 0.85

    def test_to_ids_hit_from_json_string_value(self):
        """Il bundle reale coerce il valore Evidence da stringa JSON →
        la regola deve funzionare anche con la stringa serializzata."""
        import json

        bundle = _sparse_l4_bundle(
            strong_evidence_details={
                "reputation_hit": [json.dumps(_MISP_IDS_HIT)],
            },
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"

    def test_misp_rule_wins_over_strong_signal_delegation(self):
        """Caso reale kemkes: L4 sparsa + passive alto + reputation_hit.
        Prima della regola MISP → None (delega a Foundry, che diceva
        benign). ORA → phishing diretto."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={"reputation_hit": [_MISP_IDS_HIT]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None, (
            "La regola MISP è PRIORITARIA sulla delega per segnale forte"
        )
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"

    def test_non_misp_reputation_hit_still_delegates(self):
        """Hit di un feed NON MISP (es. URLhaus: details senza
        to_ids_match) → delega a Foundry come prima."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.5,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={
                "reputation_hit": [
                    {"url": "https://example.com", "threat": "malware_download"}
                ]
            },
        )

        assert prefilter(bundle) is None, (
            "Senza to_ids_match il reputation_hit resta 'segnale da "
            "aggregare': decide Foundry"
        )

    def test_context_only_match_does_not_intercept(self):
        """Details con to_ids_match=False (solo contesto informativo)
        → MAI un Verdict phishing dal prefilter."""
        hit = dict(_MISP_IDS_HIT, to_ids_match=False, context_only=True)
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.0,
            strong_evidence_details={"reputation_hit": [hit]},
        )

        verdict = prefilter(bundle)
        # Senza altri segnali forti e con L4 sparsa → caso inconclusivo
        # (suspicious a bassa confidenza), NON phishing.
        if verdict is not None:
            assert verdict.classification == Classification.suspicious

    def test_no_reputation_hit_unaffected(self):
        """Nessun reputation_hit → il comportamento esistente resta
        identico (nessun Verdict spurio)."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            strong_evidence_details={
                "typosquat": [{"domain": "rnnovospid.cc", "brand": "Aruba",
                               "distance": 1}],
            },
        )

        assert prefilter(bundle) is None


# ---------------------------------------------------------------------------
# OpenCTI active-IOC rule — stesso trattamento deterministico del MISP
# ---------------------------------------------------------------------------

# Details reali prodotti dal provider OpenCTI (stessa forma del riepilogo
# di ``_summarise``: osservabile con un Indicator attivo).
_OPENCTI_ACTIVE_HIT = {
    "match_count": 1,
    "matched_types": ["Url"],
    "active_indicator_count": 1,
    "total_indicator_count": 1,
    "labels": ["phishing"],
    "markings": ["TLP:AMBER"],
    "created_by": ["CERT-AGID"],
    "score_min": 85,
    "score_max": 85,
    "score_avg": 85.0,
    "active_ioc_match": True,
    "context_only": False,
}


class TestOpenCtiActiveHitIntercepts:
    """Hit OpenCTI con IOC attivo → phishing deterministico dal prefilter."""

    def test_active_ioc_hit_returns_phishing_verdict(self):
        """Match su osservabile Url → phishing conf 0.95, rationale con
        label/marcatura/score, brand None (nessuna convenzione
        phishing-name affidabile su OpenCTI)."""
        bundle = _sparse_l4_bundle(
            canonical_url="https://login.inps.gov.it/pagamento",
            passive_risk_score=0.55,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={"reputation_hit": [_OPENCTI_ACTIVE_HIT]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence == 0.95, (
            f"Match sull'osservabile Url → confidenza massima, got "
            f"{verdict.confidence}"
        )
        assert verdict.brand is None
        assert "OpenCTI" in verdict.rationale
        assert "phishing" in verdict.rationale
        assert "TLP:AMBER" in verdict.rationale
        assert "Score medio: 85.0" in verdict.rationale
        assert verdict.final_url == "https://login.inps.gov.it/pagamento"

    def test_infra_only_match_lower_confidence(self):
        """Match solo su Domain-Name/IP (infrastruttura, non URL esatto)
        → phishing comunque, ma confidenza 0.85."""
        hit = dict(_OPENCTI_ACTIVE_HIT, matched_types=["Domain-Name", "IPv4-Addr"])
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            strong_evidence_details={"reputation_hit": [hit]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"
        assert verdict.confidence == 0.85

    def test_active_ioc_hit_from_json_string_value(self):
        """Il valore serializzato come stringa JSON non deve far saltare
        la regola di sicurezza (stessa robustezza della regola MISP)."""
        import json

        bundle = _sparse_l4_bundle(
            strong_evidence_details={
                "reputation_hit": [json.dumps(_OPENCTI_ACTIVE_HIT)],
            },
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"

    def test_opencti_rule_wins_over_strong_signal_delegation(self):
        """L4 sparsa + passive alto + hit OpenCTI attivo → phishing
        diretto, NON delega a Foundry."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={"reputation_hit": [_OPENCTI_ACTIVE_HIT]},
        )

        verdict = prefilter(bundle)
        assert verdict is not None, (
            "La regola OpenCTI è PRIORITARIA sulla delega per segnale forte"
        )
        assert verdict.classification == Classification.phishing
        assert verdict.produced_by == "prefilter"

    def test_context_only_match_does_not_intercept(self):
        """Osservabile senza IOC attivo (revoked/scaduto) → MAI un Verdict
        phishing dal prefilter."""
        hit = dict(_OPENCTI_ACTIVE_HIT, active_ioc_match=False, context_only=True)
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.0,
            strong_evidence_details={"reputation_hit": [hit]},
        )

        verdict = prefilter(bundle)
        # Senza altri segnali forti e con L4 sparsa → caso inconclusivo
        # (suspicious a bassa confidenza), NON phishing.
        if verdict is not None:
            assert verdict.classification == Classification.suspicious

    def test_opencti_hit_without_active_marker_still_delegates(self):
        """Details OpenCTI senza ``active_ioc_match`` → resta segnale da
        aggregare: decide Foundry."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.5,
            evidence_summary={"reputation_hit": 1},
            strong_evidence_details={
                "reputation_hit": [
                    {"match_count": 1, "matched_types": ["Url"]}
                ]
            },
        )

        assert prefilter(bundle) is None, (
            "Senza active_ioc_match il reputation_hit resta 'segnale da "
            "aggregare': decide Foundry"
        )

    def test_misp_rule_wins_over_opencti_when_both_hit(self):
        """Entrambi i feed colpiscono → vince il Verdict MISP (curatela
        IDS + estrazione brand dai tag phishing-name) e il rationale cita
        OpenCTI come corroborazione."""
        bundle = _sparse_l4_bundle(
            passive_risk_score=0.55,
            evidence_summary={"reputation_hit": 2},
            strong_evidence_details={
                "reputation_hit": [_OPENCTI_ACTIVE_HIT, _MISP_IDS_HIT],
            },
        )

        verdict = prefilter(bundle)
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.brand == "Amazon, Netflix", (
            "Con entrambi i feed vince il Verdict MISP (brand dai tag)"
        )
        assert "Confermato anche da OpenCTI" in verdict.rationale, (
            "Con un hit OpenCTI concorrente il rationale deve citarlo "
            "come corroborazione"
        )
        assert "1 osservabile (Url), 1 indicatore attivo su 1" in (
            verdict.rationale
        ), "I dettagli OpenCTI (osservabili e indicatori) vanno nel rationale"
        assert "Feed verificati" in verdict.rationale, (
            "Con due feed confermati la chiusura del rationale è al plurale"
        )
