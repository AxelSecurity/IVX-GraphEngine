"""Tests for foundry_classifier — NEVER makes real Azure calls.

All Azure API calls are mocked.  The primary concerns:
1. Every classify() call creates a NEW thread (no thread_id reuse).
2. The prompt built from the bundle does NOT leak data from previous runs.
3. When Foundry is not configured, the heuristic fallback is used.
4. The credential is selected from configuration: full service principal
   → ClientSecretCredential; otherwise DefaultAzureCredential.
5. classify() never sends image attachments (removed 2026-08-26 —
   visual content arrives as TEXT via Azure AI Vision).
"""

from __future__ import annotations

import enum
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
    real SDK installed.

    Returns ``(saved, credential_log)`` where ``credential_log`` is a
    list of ``(kind, kwargs)`` tuples recording every credential the
    classifier constructs — lets tests assert WHICH credential type
    (and with which values) was selected."""
    credential_log: list[tuple] = []

    class _DefaultCredential:
        def __init__(self):
            credential_log.append(("default", {}))

    class _ClientSecretCredential:
        def __init__(self, tenant_id=None, client_id=None, client_secret=None):
            credential_log.append(
                (
                    "client_secret",
                    {
                        "tenant_id": tenant_id,
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                )
            )

    saved = {}
    for name in ("azure", "azure.ai", "azure.ai.agents", "azure.identity"):
        saved[name] = sys.modules.get(name)
        mod = ModuleType(name)
        if name in ("azure", "azure.ai"):
            mod.__path__ = []
        sys.modules[name] = mod
    # Injected under the REAL SDK class names (AgentsClient,
    # ClientSecretCredential, DefaultAzureCredential), NOT under
    # whatever names the code under test happens to import: if the
    # classifier ever misspells an import, the in-function import fails
    # here too and the test breaks loudly instead of silently
    # self-fulfilling.
    sys.modules["azure.ai.agents"].AgentsClient = fake_client_class
    sys.modules["azure.identity"].DefaultAzureCredential = _DefaultCredential
    sys.modules["azure.identity"].ClientSecretCredential = _ClientSecretCredential
    return saved, credential_log


def _unregister_fake_azure_modules(saved):
    """Restore ``sys.modules`` to its original state."""
    for name, original in saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


class _FakeAgentsClient:
    """Stub for ``AgentsClient`` — records every ``thread_id`` it sees.

    A *single* instance is shared across all fake client instances so
    the test can inspect the full call history across multiple
    ``classify()`` invocations.  Mirrors the current SDK surface:
    namespaced sub-clients ``threads``/``messages``/``runs``/``files``.
    """

    def __init__(self):
        self._counter = 0
        self.thread_ids_created: list[str] = []
        self.thread_ids_message: list[str] = []
        self.thread_ids_run: list[str] = []
        self.thread_ids_list: list[str] = []
        self.thread_ids_delete: list[str] = []
        self.threads = _FakeThreads(self)
        self.messages = _FakeMessages(self)
        self.runs = _FakeRuns(self)


class _FakeThreads:
    """Stub for ``client.threads``."""

    def __init__(self, recorder: "_FakeAgentsClient"):
        self._r = recorder

    # -- called by _new_thread_id ------------------------------------------
    def create(self):
        self._r._counter += 1
        tid = f"thread-{self._r._counter}"
        self._r.thread_ids_created.append(tid)
        return SimpleNamespace(id=tid)

    def delete(self, thread_id):
        self._r.thread_ids_delete.append(thread_id)


class _FakeMessageRole(enum.Enum):
    """Mirror of the REAL SDK surface (learned live 2026-08-26 via
    diagnostic dump on the configured Foundry endpoint):

    ``msg.role`` is a ``MessageRole`` ENUM whose ``.value`` is
    ``'assistant'``; ``str(role)`` is ``"MessageRole.AGENT"``.  A plain
    ``msg.role == "agent"`` comparison in the classifier silently matches
    NOTHING — this fake uses a real enum (not a str) so that any
    regression to string comparison breaks the tests loudly.
    """

    AGENT = "assistant"
    USER = "user"


class _FakeMessageTextContent:
    """Mirror of the REAL ``MessageTextContent`` block: the text sits in
    ``.value`` directly (no ``.text.value`` wrapper)."""

    def __init__(self, value: str):
        self.value = value


class _FakeMessages:
    """Stub for ``client.messages``."""

    def __init__(self, recorder: "_FakeAgentsClient"):
        self._r = recorder

    def create(self, thread_id, role, content):
        self._r.thread_ids_message.append(thread_id)

    def list(self, thread_id):
        self._r.thread_ids_list.append(thread_id)
        block = _FakeMessageTextContent(
            '{"classification":"phishing","confidence":0.92,"rationale":"mock"}'
        )
        msg = SimpleNamespace(role=_FakeMessageRole.AGENT, content=[block])
        # Current SDK returns an ItemPaged — iterable, no .data attribute.
        return [msg]


class _FakeRuns:
    """Stub for ``client.runs``."""

    def __init__(self, recorder: "_FakeAgentsClient"):
        self._r = recorder

    def create_and_process(self, thread_id, agent_id, instructions):
        self._r.thread_ids_run.append(thread_id)
        return SimpleNamespace(status="completed")


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

        Every ``classify()`` invocation creates a fresh ``AgentsClient``,
        so the fake client reuses a single shared ``_FakeAgentsClient``
        instance to accumulate the full call history across all three calls.

        Assertions verify that:

        1. ``threads.create`` is called exactly once per ``classify()``.
        2. Every ``thread_id`` returned by ``threads.create`` is distinct.
        3. The SAME ``thread_id`` flows through the entire call chain
           (messages.create → runs.create_and_process → messages.list →
           threads.delete), in order, with no reuse or misalignment.
        """
        fake_agents = _FakeAgentsClient()

        # -- fake client constructor, exposes the shared sub-clients -------
        class _FakeClient:
            def __init__(self, endpoint, credential):
                self.threads = fake_agents.threads
                self.messages = fake_agents.messages
                self.runs = fake_agents.runs

        saved, _ = _register_fake_azure_modules(_FakeClient)
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
        assert "screenshot_paths" not in param_names, (
            f"classify() must NOT accept screenshot_paths — image "
            f"attachments were removed (visual content arrives as TEXT "
            f"via Azure AI Vision); signature is ({', '.join(param_names)})"
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
            await _call_foundry_agent("prompt")

    @pytest.mark.asyncio
    async def test_missing_agent_id_raises(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "azure_foundry_endpoint",
            "https://example.openai.azure.com",
        )
        monkeypatch.setattr(settings, "azure_foundry_agent_id", None)
        with pytest.raises(_FoundryNotConfigured):
            await _call_foundry_agent("prompt")


# ---------------------------------------------------------------------------
# Tests — credential selection (service principal vs DefaultAzureCredential)
# ---------------------------------------------------------------------------


class TestCredentialSelection:
    """Il classificatore seleziona la credential dalla configurazione:
    service principal completo → ClientSecretCredential coi valori del
    config; altrimenti → DefaultAzureCredential.  Nessun'altra chiamata
    Azure viene fatta."""

    async def _classify_with_fake_and_return_credential_log(self, monkeypatch):
        """Esegue classify() con i moduli Azure fake, ritorna il log delle
        credential costruite dal codice di produzione."""
        monkeypatch.setattr(
            settings,
            "azure_foundry_endpoint",
            "https://fake-foundry.openai.azure.com",
        )
        monkeypatch.setattr(settings, "azure_foundry_agent_id", "fake-agent-id")

        fake_agents = _FakeAgentsClient()

        class _FakeClient:
            def __init__(self, endpoint, credential):
                self.threads = fake_agents.threads
                self.messages = fake_agents.messages
                self.runs = fake_agents.runs

        saved, credential_log = _register_fake_azure_modules(_FakeClient)
        try:
            verdict = await classify(_sample_bundle())
        finally:
            _unregister_fake_azure_modules(saved)

        assert verdict.produced_by == "foundry"
        return credential_log

    @pytest.mark.asyncio
    async def test_service_principal_uses_client_secret_credential(
        self, monkeypatch
    ):
        """Tenant+client+secret → ClientSecretCredential costruita coi
        valori del config; DefaultAzureCredential MAI toccata."""
        monkeypatch.setattr(settings, "azure_tenant_id", "tenant-123")
        monkeypatch.setattr(settings, "azure_client_id", "client-456")
        monkeypatch.setattr(settings, "azure_client_secret", "secret-789")

        log = await self._classify_with_fake_and_return_credential_log(
            monkeypatch
        )

        assert log == [
            (
                "client_secret",
                {
                    "tenant_id": "tenant-123",
                    "client_id": "client-456",
                    "client_secret": "secret-789",
                },
            )
        ]

    @pytest.mark.asyncio
    async def test_no_service_principal_uses_default_credential(self, monkeypatch):
        """Senza le tre variabili → DefaultAzureCredential (es. az login,
        managed identity); ClientSecretCredential MAI toccata."""
        monkeypatch.setattr(settings, "azure_tenant_id", None)
        monkeypatch.setattr(settings, "azure_client_id", None)
        monkeypatch.setattr(settings, "azure_client_secret", None)

        log = await self._classify_with_fake_and_return_credential_log(
            monkeypatch
        )

        assert log == [("default", {})]

    @pytest.mark.asyncio
    async def test_partial_service_principal_falls_back_to_default(
        self, monkeypatch
    ):
        """Coppia incompleta (manca il secret) → DefaultAzureCredential:
        la property richiede TUTTE e tre le variabili."""
        monkeypatch.setattr(settings, "azure_tenant_id", "tenant-123")
        monkeypatch.setattr(settings, "azure_client_id", "client-456")
        monkeypatch.setattr(settings, "azure_client_secret", None)

        log = await self._classify_with_fake_and_return_credential_log(
            monkeypatch
        )

        assert log == [("default", {})]


# ---------------------------------------------------------------------------
# Smoke test — REAL SDK import (integration)
# ---------------------------------------------------------------------------


def _purge_injected_azure_modules():
    """Remove any fake ``azure.*`` modules from ``sys.modules`` so a REAL
    import below can never silently resolve to a test double."""
    for name in list(sys.modules):
        if name == "azure" or name.startswith("azure."):
            sys.modules.pop(name, None)


@pytest.mark.integration
def test_real_sdk_exposes_ai_project_client():
    """REAL import of ``AIProjectClient`` — no ``sys.modules`` injection.

    Safety net against exactly the bug this file fixed: the fake-module
    registry used to inject the stub under whatever name the classifier
    imported, so a typo in the SDK class name could ship silently.

    Requires the real ``azure-ai-projects`` SDK installed; excluded from
    the default suite (pytest.ini ``addopts = -m "not integration"``).
    """
    _purge_injected_azure_modules()
    from azure.ai.projects import AIProjectClient  # noqa: F401

    assert AIProjectClient is not None


@pytest.mark.integration
def test_real_sdk_exposes_agents_client():
    """REAL import of ``AgentsClient`` — the conversational client the
    classifier now talks to (``azure-ai-agents``, split out of
    ``azure-ai-projects`` in current SDK versions)."""
    _purge_injected_azure_modules()
    from azure.ai.agents import AgentsClient  # noqa: F401

    assert AgentsClient is not None
