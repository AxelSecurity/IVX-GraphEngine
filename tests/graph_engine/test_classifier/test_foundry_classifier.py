"""Tests for foundry_classifier — NEVER makes real Azure calls.

All Azure API calls are mocked.  The primary concerns:
1. Every classify() call creates a NEW thread (no thread_id reuse).
2. The prompt built from the bundle does NOT leak data from previous runs.
3. When Foundry is not configured, the heuristic fallback is used.
"""

from __future__ import annotations

import sys
import uuid
from types import ModuleType, SimpleNamespace

import pytest

from graph_engine.config import settings
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
# Fake Azure SDK boundary — lets _call_foundry_agent run its REAL code
# against a stub instead of importing the (uninstalled) azure-ai-projects.
# ---------------------------------------------------------------------------


def _register_fake_azure_modules(fake_client_class):
    """Register fake ``azure.*`` modules in ``sys.modules`` so the
    local imports inside ``_call_foundry_agent`` succeed without the
    real SDK installed."""
    saved = {}
    for name in ("azure", "azure.ai", "azure.ai.projects", "azure.identity"):
        saved[name] = sys.modules.get(name)
        mod = ModuleType(name)
        if name in ("azure", "azure.ai"):
            mod.__path__ = []
        sys.modules[name] = mod
    sys.modules["azure.ai.projects"].AIProjectsClient = fake_client_class
    sys.modules["azure.identity"].DefaultAzureCredential = lambda: None
    return saved


def _unregister_fake_azure_modules(saved):
    """Restore ``sys.modules`` to its original state."""
    for name, original in saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


class _FakeAgents:
    """Stub for ``client.agents`` — records every ``thread_id`` it sees.

    A *single* instance is shared across all fake client instances so
    the test can inspect the full call history across multiple
    ``classify()`` invocations.
    """

    def __init__(self):
        self._counter = 0
        self.thread_ids_created: list[str] = []
        self.thread_ids_message: list[str] = []
        self.thread_ids_run: list[str] = []
        self.thread_ids_list: list[str] = []
        self.thread_ids_delete: list[str] = []

    # -- methods called by _new_thread_id ---------------------------------
    def create_thread(self):
        self._counter += 1
        tid = f"thread-{self._counter}"
        self.thread_ids_created.append(tid)
        return SimpleNamespace(id=tid)

    # -- methods called by _call_foundry_agent ----------------------------
    def create_message(self, thread_id, role, content, attachments=None):
        self.thread_ids_message.append(thread_id)

    def create_and_process_run(self, thread_id, agent_id, instructions):
        self.thread_ids_run.append(thread_id)
        return SimpleNamespace(status="completed")

    def list_messages(self, thread_id):
        self.thread_ids_list.append(thread_id)
        block = SimpleNamespace()
        block.text = SimpleNamespace(
            value='{"classification":"phishing","confidence":0.92,"rationale":"mock"}'
        )
        msg = SimpleNamespace(role="agent", content=[block])
        return SimpleNamespace(data=[msg])

    def delete_thread(self, thread_id):
        self.thread_ids_delete.append(thread_id)


# ---------------------------------------------------------------------------
# Tests — stateless constraint
# ---------------------------------------------------------------------------


class TestStatelessThreadCreation:
    """Every classify() call MUST create a fresh thread."""

    @pytest.mark.asyncio
    async def test_real_code_never_reuses_thread_across_classify_calls(
        self, monkeypatch
    ):
        """Execute the REAL ``_new_thread_id`` and ``_call_foundry_agent``
        code path, faking only the Azure SDK boundary (``sys.modules``).

        Every ``classify()`` invocation creates a fresh ``AIProjectsClient``,
        so the fake client reuses a single shared ``_FakeAgents`` instance
        to accumulate the full call history across all three calls.

        Assertions verify that:

        1. ``create_thread`` is called exactly once per ``classify()``.
        2. Every ``thread_id`` returned by ``create_thread`` is distinct.
        3. The SAME ``thread_id`` flows through the entire call chain
           (create_message → create_and_process_run → list_messages →
           delete_thread), in order, with no reuse or misalignment.
        """
        fake_agents = _FakeAgents()

        # -- fake client constructor, captures the shared agents ----------
        class _FakeClient:
            def __init__(self, endpoint, credential):
                self.agents = fake_agents

        saved = _register_fake_azure_modules(_FakeClient)
        try:
            monkeypatch.setattr(
                settings,
                "azure_foundry_endpoint",
                "https://fake-fallback.openai.azure.com",
            )
            monkeypatch.setattr(
                settings, "azure_foundry_agent_id", "fake-agent-id"
            )

            v1 = await classify(_sample_bundle())
            v2 = await classify(_sample_bundle())
            v3 = await classify(_sample_bundle())

            # ── Assertions ──────────────────────────────────────────────
            # 1. create_thread called exactly 3 times
            assert len(fake_agents.thread_ids_created) == 3, (
                f"create_thread called {len(fake_agents.thread_ids_created)} "
                f"times, expected 3"
            )

            # 2. All 3 thread IDs are distinct
            assert len(set(fake_agents.thread_ids_created)) == 3, (
                f"Thread IDs not unique: {fake_agents.thread_ids_created}"
            )

            # 3. create_message received the SAME IDs, in the SAME order
            assert fake_agents.thread_ids_message == fake_agents.thread_ids_created, (
                f"create_message IDs {fake_agents.thread_ids_message} "
                f"≠ created IDs {fake_agents.thread_ids_created}"
            )

            # 4. create_and_process_run received the SAME IDs, in order
            assert fake_agents.thread_ids_run == fake_agents.thread_ids_created, (
                f"create_and_process_run IDs {fake_agents.thread_ids_run} "
                f"≠ created IDs {fake_agents.thread_ids_created}"
            )

            # 5. list_messages received the SAME IDs, in order
            assert fake_agents.thread_ids_list == fake_agents.thread_ids_created, (
                f"list_messages IDs {fake_agents.thread_ids_list} "
                f"≠ created IDs {fake_agents.thread_ids_created}"
            )

            # 6. delete_thread received the SAME IDs, in order
            assert fake_agents.thread_ids_delete == fake_agents.thread_ids_created, (
                f"delete_thread IDs {fake_agents.thread_ids_delete} "
                f"≠ created IDs {fake_agents.thread_ids_created}"
            )

            # 7. Explicit values — each call gets a fresh, incrementing ID
            assert fake_agents.thread_ids_created == [
                "thread-1", "thread-2", "thread-3",
            ], (
                f"Expected ['thread-1', 'thread-2', 'thread-3'], "
                f"got {fake_agents.thread_ids_created}"
            )

            # 8. Verdicts are correct
            for v in (v1, v2, v3):
                assert v is not None
                assert v.classification == Classification.phishing
                assert v.produced_by == "foundry"

        finally:
            _unregister_fake_azure_modules(saved)

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
    async def test_foundry_not_configured_falls_back(self, monkeypatch):
        """When env vars are missing, return heuristic verdict (no crash)."""
        monkeypatch.setattr(settings, "azure_foundry_endpoint", None)
        monkeypatch.setattr(settings, "azure_foundry_agent_id", None)

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
    async def test_missing_env_vars_raises(self, monkeypatch):
        monkeypatch.setattr(settings, "azure_foundry_endpoint", None)
        monkeypatch.setattr(settings, "azure_foundry_agent_id", None)
        with pytest.raises(_FoundryNotConfigured):
            await _call_foundry_agent("prompt", [])

    @pytest.mark.asyncio
    async def test_missing_agent_id_raises(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "azure_foundry_endpoint",
            "https://example.openai.azure.com",
        )
        monkeypatch.setattr(settings, "azure_foundry_agent_id", None)
        with pytest.raises(_FoundryNotConfigured):
            await _call_foundry_agent("prompt", [])
