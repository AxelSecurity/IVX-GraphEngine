"""L5 classifier via Azure AI Foundry Agents — stateless, one-shot.

CRITICAL DESIGN CONSTRAINT — read before modifying:
    Every call to ``classify()`` creates a **new** thread and is
    completely isolated from previous calls.  Thread IDs are NEVER
    reused across analyses.

    WHY: during early testing (2026-08) we observed that the Foundry
    Agent's built-in conversation memory caused false positives when
    thread state from a previous phishing case leaked into the context
    of an unrelated benign URL.  The agent would "remember" credential
    fields it saw in case N and hallucinate them in case N+1, producing
    high-confidence phishing verdicts for legitimate sites.

    Stateless isolation is therefore NON-NEGOTIABLE for correctness.
    See docs/ARCHITECTURE.md § L5 — Classificazione.

    NOTE — no image attachments: visual content reaches the model as
    TEXT inside the bundle (OCR + Brand Detection via Azure AI Vision).
    The configured model (gpt-5-mini) rejects image content types, so
    screenshot upload/attach was removed entirely (2026-08-26).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from graph_engine.config import settings
from graph_engine.models import Classification, Verdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default system prompt — shipped as a file next to this module
# ---------------------------------------------------------------------------
_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "system_prompt.txt")


def _load_system_prompt() -> str:
    try:
        with open(_PROMPT_PATH, encoding="utf-8") as fh:
            return fh.read().strip()
    except FileNotFoundError:
        return "You are a phishing-classification agent. Return JSON."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def classify(bundle: dict) -> Verdict:
    """Send *bundle* to the Foundry Agent, return Verdict.

    Visual content reaches the agent as TEXT inside the bundle (OCR +
    Brand Detection via Azure AI Vision) — no image attachments are
    ever sent (see module docstring).

    The agent is expected to return a JSON object matching the Verdict
    schema (see ``system_prompt.txt``).  This function parses that JSON
    and validates it against the Pydantic model.

    If the SDK is not installed or credentials are missing, falls back
    to a deterministic heuristic verdict (see ``_heuristic_fallback``).
    """

    prompt_text = _build_user_message(bundle)
    target_id = bundle.get("target_id", "")

    try:
        raw_json = await _call_foundry_agent(prompt_text)
    except _FoundryNotConfigured as exc:
        # Il motivo reale (env mancanti O SDK non installato) è nel
        # messaggio dell'eccezione: loggarlo evita il falso allarme
        # "not configured" quando il .env è a posto ma manca un pacchetto.
        logger.warning(
            "Azure Foundry unavailable (%s) — falling back to "
            "heuristic verdict",
            exc,
        )
        return _heuristic_fallback(bundle)
    except Exception as exc:
        logger.error("Foundry call failed: %s", exc, exc_info=True)
        return _heuristic_fallback(bundle)

    # Parse and validate the agent response
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        logger.warning("Foundry returned invalid JSON — falling back")
        return _heuristic_fallback(bundle)

    # Coerce classification string to enum
    classification_str = data.get("classification", "suspicious")
    try:
        classification = Classification(classification_str)
    except ValueError:
        classification = Classification.suspicious

    confidence = float(data.get("confidence", 0.3))
    # Clamp
    confidence = max(0.0, min(1.0, confidence))

    return Verdict(
        target_id=target_id,  # type: ignore[arg-type]
        classification=classification,
        confidence=confidence,
        produced_by="foundry",
        brand=data.get("brand") or None,
        kit_family=data.get("kit_family") or None,
        rationale=data.get("rationale") or None,
        final_url=data.get("final_url") or None,
        exfil_endpoint=data.get("exfil_endpoint") or None,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _new_thread_id(client) -> str:
    """Create a NEW Foundry thread and return its ID.

    CRITICAL: this function is called once per ``classify()`` invocation.
    Thread IDs are NEVER cached, reused, or stored in module-level state.
    See module-level docstring for the historical bug that motivates this
    constraint (cross-session memory caused false positives when thread
    state leaked between unrelated analyses).

    Extracted as a separate function so tests can mock it directly and
    verify that *every* call produces a fresh, distinct thread ID.
    """
    thread = client.threads.create()
    return thread.id


def _build_user_message(bundle: dict) -> str:
    """Convert bundle to prompt text and wrap it for the agent."""
    from graph_engine.classifier.evidence_bundle import bundle_to_prompt_text

    body = bundle_to_prompt_text(bundle)
    total_chars = len(body)
    return (
        "Please classify the following URL exploration result.  "
        "Refer ONLY to the data provided below.  "
        "If the data is insufficient, say so and return low confidence.\n\n"
        f"{body}\n\n"
        f"--- end bundle ({total_chars} chars) ---"
    )


async def _call_foundry_agent(prompt: str) -> str:
    """Run the (blocking) Foundry SDK flow in a worker thread.

    The AgentsClient SDK is fully synchronous: ``create_and_process``
    blocks for the whole run duration.  Running it on the event loop
    would freeze the entire API server (10-40s+ with a real agent) and
    prevent the Trellix 48s response timeout from ever firing — the
    frontdoor deadline would be missed silently.  ``asyncio.to_thread``
    keeps the loop responsive while the agent runs.

    NO ``asyncio.wait_for`` around the thread: the Foundry run has no
    time cap by design (user decision — L5 must not be limited).  The
    caller (``classify``) stays cancellable-cooperative on the loop.
    """
    # NESSUN wait_for: il run Foundry resta senza tetto (decisione utente)
    return await asyncio.to_thread(_call_foundry_agent_sync, prompt)


def _call_foundry_agent_sync(prompt: str) -> str:
    """Create a fresh thread, send the prompt, run, and return the reply.

    Blocking body executed in a worker thread (see ``_call_foundry_agent``).
    Raises ``_FoundryNotConfigured`` if env vars are missing.
    """

    endpoint = settings.azure_foundry_endpoint or ""
    agent_id = settings.azure_foundry_agent_id or ""

    if not endpoint or not agent_id:
        raise _FoundryNotConfigured("AZURE_FOUNDRY_ENDPOINT or AGENT_ID not set")

    # Import here so the module is importable without the SDK installed
    try:
        from azure.ai.agents import AgentsClient
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
    except ImportError:
        raise _FoundryNotConfigured(
            "Azure Agents SDK not installed; run: "
            "pip install azure-ai-agents azure-ai-projects azure-identity"
        )

    if settings.service_principal_configured:
        # Credenziali dal .env: pydantic-settings NON le esporta in
        # os.environ, quindi DefaultAzureCredential non le vedrebbe —
        # si costruisce esplicitamente il ClientSecretCredential.
        credential = ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
        )
    else:
        credential = DefaultAzureCredential()
    # AgentsClient (azure-ai-agents) is the CONVERSATIONAL client — threads,
    # messages, runs.  It is split out of azure-ai-projects in current SDK
    # versions: AIProjectClient.agents there only manages agent DEFINITIONS.
    client = AgentsClient(endpoint=endpoint, credential=credential)

    # ── CRITICAL: always create a NEW thread ─────────────────────────────
    # See module-level docstring for the rationale.  One thread per call,
    # deleted in the finally block below — never reused.
    thread_id = _new_thread_id(client)
    # ─────────────────────────────────────────────────────────────────────

    system_prompt = _load_system_prompt()

    try:
        # Post the user message
        client.messages.create(
            thread_id=thread_id,
            role="user",
            content=prompt,
        )

        # Create and wait for the run
        run = client.runs.create_and_process(
            thread_id=thread_id,
            agent_id=agent_id,
            instructions=system_prompt,
        )

        if run.status not in ("completed", "requires_action"):
            logger.warning("Foundry run ended with status: %s", run.status)
            raise RuntimeError(f"Agent run failed: {run.status}")

        # Collect the agent's text response.  Current SDK returns an
        # ItemPaged — materialize it once.
        #
        # LIVE SDK FACTS (learned 2026-08-26 via diagnostic dump):
        #  - msg.role is a MessageRole ENUM whose value is 'assistant';
        #    str(role) is "MessageRole.AGENT", so only .value comparisons
        #    work.
        #  - text blocks are MessageTextContent with the text directly in
        #    .value (no .text.value wrapper).
        messages = list(client.messages.list(thread_id=thread_id))
        for msg in messages:
            role_value = getattr(msg.role, "value", msg.role)
            if str(role_value).lower() not in ("agent", "assistant"):
                continue
            if not msg.content:
                continue
            text_parts = []
            for block in msg.content:
                # Current SDK: MessageTextContent.value holds the text.
                # Legacy variants: block.text may be a plain str or an
                # annotation block exposing .text.value.
                value = getattr(block, "value", None)
                if isinstance(value, str):
                    text_parts.append(value)
                    continue
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    text_parts.append(text)
                elif hasattr(text, "value") and isinstance(
                    getattr(text, "value", None), str
                ):
                    text_parts.append(text.value)
            if text_parts:
                return "\n".join(text_parts)

        return ""

    finally:
        # Clean up the ephemeral thread — no cross-session leakage
        try:
            client.threads.delete(thread_id)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Heuristic fallback (runs when Foundry is unavailable)
# ---------------------------------------------------------------------------


def _heuristic_fallback(bundle: dict) -> Verdict:
    """Deterministic, conservative verdict for when the model is unreachable.

    This is intentionally pessimistic — it errs toward "suspicious" with
    low confidence rather than guessing.
    """
    flags = bundle.get("flags", {})
    graph_states = bundle.get("states", [])
    total_fields = sum(
        len(st.get("form_fields", [])) for st in graph_states
    )

    # If nothing was collected (1 state, no fields, no errors), data is sparse
    if bundle.get("num_states", 0) <= 1 and total_fields == 0:
        return Verdict(
            target_id=bundle.get("target_id", ""),
            classification=Classification.suspicious,
            confidence=0.1,
            produced_by="heuristic_fallback",
            rationale=(
                "Heuristic fallback (Foundry unavailable): single state with "
                "no visible form fields — insufficient data for classification."
            ),
        )

    # Multiple states with form fields → weak phishing signal
    if total_fields >= 2:
        return Verdict(
            target_id=bundle.get("target_id", ""),
            classification=Classification.suspicious,
            confidence=0.2,
            produced_by="heuristic_fallback",
            rationale=(
                "Heuristic fallback (Foundry unavailable): multiple states with "
                f"form fields ({total_fields} total) detected — cannot exclude "
                "phishing without model analysis."
            ),
        )

    return Verdict(
        target_id=bundle.get("target_id", ""),
        classification=Classification.suspicious,
        confidence=0.15,
        produced_by="heuristic_fallback",
        rationale=(
            "Heuristic fallback (Foundry unavailable): insufficient signals "
            "for automated classification."
        ),
    )


class _FoundryNotConfigured(Exception):
    pass
