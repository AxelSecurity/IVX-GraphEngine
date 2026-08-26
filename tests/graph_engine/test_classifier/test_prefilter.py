"""Tests for deterministic prefilter — must only intercept trivially bad cases."""

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
        "leaf_states": [
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
            "leaf_states": [
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
            "leaf_states": [
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
            "leaf_states": [],
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
            "leaf_states": [
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
            "leaf_states": [
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
            leaf_states=[
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
            "leaf_states": [],
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
