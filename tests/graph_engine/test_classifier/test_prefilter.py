"""Tests for deterministic prefilter — must only intercept trivially bad cases."""

from __future__ import annotations

import uuid

import pytest

from graph_engine.classifier.prefilter import prefilter
from graph_engine.models import Classification


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


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
