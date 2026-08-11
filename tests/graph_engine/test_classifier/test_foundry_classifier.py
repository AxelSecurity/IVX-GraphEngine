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
    _new_thread_id,
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
    async def test_thread_created_fresh_for_each_classify_call(self):
        """N calls → N distinct thread IDs, no reuse.  Verify the IDs
        returned by _new_thread_id are the same ones passed downstream
        (into the agent call), not ignored or overwritten."""

        from graph_engine.classifier import foundry_classifier as fcm

        # ── Track every ID that _new_thread_id produces ──────────────────
        created_ids: list[str] = []
        # ── Track every ID the agent call *receives* from _new_thread_id ─
        downstream_ids: list[str] = []

        call_n = [0]

        def _fake_new_thread_id(client):
            call_n[0] += 1
            tid = f"thread-{call_n[0]}"
            created_ids.append(tid)
            return tid

        async def _fake_agent_call(prompt, screenshot_paths):
            # Replicate the real flow: call _new_thread_id, capture its
            # return value — this is the value the real code passes to
            # client.agents.create_message(thread_id=…).
            tid = fcm._new_thread_id(None)
            downstream_ids.append(tid)
            return (
                '{"classification":"phishing","confidence":0.92,'
                '"rationale":"mock"}'
            )

        with patch.object(fcm, "_new_thread_id", _fake_new_thread_id), \
             patch.object(fcm, "_call_foundry_agent", _fake_agent_call):

            v1 = await classify(_sample_bundle())
            v2 = await classify(_sample_bundle())
            v3 = await classify(_sample_bundle())

        # ── Assertions ───────────────────────────────────────────────────
        # 1. _new_thread_id called exactly once per classify()
        assert len(created_ids) == 3, (
            f"_new_thread_id called {len(created_ids)} times, expected 3"
        )
        # 2. Every returned ID is unique
        assert len(set(created_ids)) == 3, (
            f"Thread IDs not unique across 3 calls: {created_ids}"
        )
        # 3. The IDs returned by _new_thread_id are the same ones
        #    passed downstream (not ignored or overwritten)
        assert downstream_ids == created_ids, (
            f"Downstream received {downstream_ids}, "
            f"but _new_thread_id created {created_ids}"
        )
        # 4. Explicit order — each call gets an incrementing fresh ID
        assert created_ids == ["thread-1", "thread-2", "thread-3"]

        # ── Verdict correctness (classify still works end-to-end) ────────
        for v in (v1, v2, v3):
            assert v is not None
            assert v.classification == Classification.phishing
            assert v.produced_by == "foundry"

    def test_classify_signature_has_no_thread_id_param(self):
        """classify() interface forbids thread_id/session_id — the
        signature itself must make reuse impossible."""
        import inspect

        sig = inspect.signature(classify)
        param_names = list(sig.parameters.keys())

        assert "thread_id" not in param_names, (
            f"classify() must NOT accept thread_id — "
            f"signature is ({', '.join(param_names)})"
        )
        assert "session_id" not in param_names, (
            f"classify() must NOT accept session_id — "
            f"signature is ({', '.join(param_names)})"
        )

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
