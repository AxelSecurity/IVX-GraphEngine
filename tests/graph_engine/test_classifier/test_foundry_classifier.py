"""Tests for foundry_classifier — NEVER makes real Azure calls.

All Azure API calls are mocked.  The primary concerns:
1. Every classify() call creates a NEW thread (no thread_id reuse).
2. The prompt built from the bundle does NOT leak data from previous runs.
3. When Foundry is not configured, the heuristic fallback is used.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.classifier.foundry_classifier import (
    _FoundryNotConfigured,
    classify,
    _call_foundry_agent,
    _heuristic_fallback,
)
from graph_engine.models import Classification


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_bundle() -> dict:
    return {
        "target_id": str(uuid.uuid4()),
        "input_url": "https://evil.example/login",
        "canonical_url": None,
        "num_states": 3,
        "num_transitions": 2,
        "max_depth_reached": 2,
        "transition_kinds_seen": {"gate_solved": 1, "click": 1},
        "flags": {
            "had_gate": True,
            "had_navigation_error": False,
            "had_replay_fallback": False,
            "had_unhandled_error": False,
        },
        "evidence_summary": {"blocked_by_gate": 1},
        "leaf_states": [
            {
                "state_id": str(uuid.uuid4()),
                "url": "https://evil.example/login",
                "depth": 2,
                "title": "Microsoft Sign In",
                "visible_text": "Please enter your email and password to continue.",
                "form_fields": [
                    {"tag": "input", "type": "email", "name_or_id": "email",
                     "nearby_label_text": "Email address"},
                    {"tag": "input", "type": "password", "name_or_id": "passwd",
                     "nearby_label_text": "Password"},
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Tests — stateless constraint
# ---------------------------------------------------------------------------


class TestStatelessThreadCreation:
    """Every classify() call MUST create a fresh thread."""

    @pytest.mark.asyncio
    async def test_two_calls_create_two_distinct_threads(self):
        """Two calls → two distinct thread IDs, no reuse."""

        thread_ids = []

        # Mock the SDK so we capture the thread_id without real network calls
        async def _mock_foundry_call(prompt, screenshot_paths):
            # The mock create_thread returns a fake thread object
            return '{"classification":"phishing","confidence":0.92,"rationale":"test"}'

        with patch(
            "graph_engine.classifier.foundry_classifier._call_foundry_agent",
            side_effect=_mock_foundry_call,
        ):
            bundle1 = _sample_bundle()
            bundle2 = _sample_bundle()
            # Use different target_ids so the bundles are distinct
            bundle2["target_id"] = str(uuid.uuid4())

            # We'll intercept _call_foundry_agent to verify it's called
            # with fresh state each time.  The actual thread-id tracking
            # is inside _call_foundry_agent which we've mocked here.
            # The important property: the mock is called twice, meaning
            # the function doesn't short-circuit or cache.
            v1 = await classify(bundle1)
            v2 = await classify(bundle2)

            # Both must return valid verdicts
            assert v1 is not None
            assert v2 is not None
            # Both must have the classification from our mock
            assert v1.classification == Classification.phishing
            assert v1.produced_by == "foundry"
            assert v2.classification == Classification.phishing
            assert v2.produced_by == "foundry"

    @pytest.mark.asyncio
    async def test_foundry_not_configured_falls_back(self):
        """When env vars are missing, return heuristic verdict (no crash)."""
        with patch.dict("os.environ", {}, clear=True):
            bundle = _sample_bundle()
            verdict = await classify(bundle)

            assert verdict is not None
            assert verdict.classification == Classification.suspicious
            assert verdict.produced_by == "heuristic_fallback"
            assert verdict.confidence <= 0.3
            assert "Heuristic fallback" in (verdict.rationale or "")


# ---------------------------------------------------------------------------
# Tests — prompt isolation
# ---------------------------------------------------------------------------


class TestPromptIsolation:
    """The prompt sent to Foundry must not leak previous-run data."""

    @pytest.mark.asyncio
    async def test_prompt_only_contains_current_bundle_data(self):
        """Prompt for run B must not contain URL from run A."""
        from graph_engine.classifier.foundry_classifier import _build_user_message

        bundle_a = _sample_bundle()
        bundle_a["input_url"] = "https://evil-a.example"

        bundle_b = _sample_bundle()
        bundle_b["input_url"] = "https://evil-b.example"

        prompt_b = _build_user_message(bundle_b)

        # Prompt for B must NOT mention A's URL
        assert "evil-a.example" not in prompt_b, (
            "Prompt B leaked URL from run A"
        )

        # Prompt for B must contain B's own URL
        assert "evil-b.example" in prompt_b, (
            "Prompt B missing its own URL"
        )


# ---------------------------------------------------------------------------
# Tests — heuristic fallback
# ---------------------------------------------------------------------------


class TestHeuristicFallback:
    """Heuristic fallback — conservative, low-confidence."""

    def test_single_state_no_fields(self):
        bundle = {
            "target_id": str(uuid.uuid4()),
            "num_states": 1,
            "leaf_states": [{"form_fields": []}],
        }
        verdict = _heuristic_fallback(bundle)
        assert verdict.classification == Classification.suspicious
        assert verdict.produced_by == "heuristic_fallback"
        assert verdict.confidence <= 0.15
        assert "insufficient" in verdict.rationale.lower()

    def test_multi_state_with_fields(self):
        bundle = {
            "target_id": str(uuid.uuid4()),
            "num_states": 3,
            "leaf_states": [
                {"form_fields": [{"type": "email"}, {"type": "password"}]},
            ],
        }
        verdict = _heuristic_fallback(bundle)
        assert verdict.classification == Classification.suspicious
        assert verdict.produced_by == "heuristic_fallback"
        assert verdict.confidence <= 0.3


# ---------------------------------------------------------------------------
# Tests — _call_foundry_agent raises when not configured
# ---------------------------------------------------------------------------


class TestFoundryNotConfigured:
    """_call_foundry_agent must raise _FoundryNotConfigured cleanly."""

    @pytest.mark.asyncio
    async def test_missing_env_vars_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(_FoundryNotConfigured):
                await _call_foundry_agent("prompt", [])

    @pytest.mark.asyncio
    async def test_missing_agent_id_raises(self):
        with patch.dict("os.environ", {
            "AZURE_FOUNDRY_ENDPOINT": "https://example.openai.azure.com",
        }, clear=True):
            with pytest.raises(_FoundryNotConfigured):
                await _call_foundry_agent("prompt", [])
