"""Domain model for the Dynamic State-Graph Engine.

Five entities implemented as Pydantic v2 models:
- AnalysisTarget, State, Transition, Evidence, Verdict
- TransitionKind enum (9 navigation types)
- Classification enum for Verdict outcome.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TransitionKind(str, Enum):
    """Typed arc between two States in the exploration graph."""

    http_3xx = "http_3xx"
    meta_refresh = "meta_refresh"
    js_location = "js_location"
    history_push = "history_push"
    click = "click"
    form_submit = "form_submit"
    new_tab = "new_tab"
    gate_solved = "gate_solved"
    ws_message = "ws_message"


class TargetStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"


class EvidenceScope(str, Enum):
    target = "target"
    state = "state"
    transition = "transition"


class Classification(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    phishing = "phishing"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class AnalysisTarget(BaseModel):
    """Unit of work — a single input URL to explore.

    Three distinct URL fields with three distinct meanings::

        input_url     — raw URL as entered by the user / upstream system
        canonical_url — L0-normalised URL (refang → unwrap → canonicalize)
                        used as the actual exploration start point
        final_url     — URL where L4 exploration landed after redirects /
                        navigation (set by the explorer post-goto)
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    input_url: str
    canonical_url: Optional[str] = None
    url_hash: Optional[str] = None
    final_url: Optional[str] = None
    status: TargetStatus = TargetStatus.queued
    root_state_id: Optional[uuid.UUID] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class State(BaseModel):
    """Graph node — uniquely identified by (target_id, url, dom_hash)."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_id: uuid.UUID
    url: str
    dom_hash: str
    depth: int = 0
    screenshot_ref: Optional[str] = None
    har_ref: Optional[str] = None


class Transition(BaseModel):
    """Typed arc between two States in the exploration graph."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_id: uuid.UUID
    from_state: uuid.UUID
    to_state: uuid.UUID
    kind: TransitionKind
    trigger: Optional[dict] = None
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Evidence(BaseModel):
    """Atomic signal with full provenance."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_id: uuid.UUID
    scope: EvidenceScope
    scope_id: uuid.UUID
    layer: str  # L0 .. L5
    key: str
    value: str
    weight: float = 1.0
    produced_by: str
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Verdict(BaseModel):
    """Aggregated outcome after exploration budget is exhausted.

    ``produced_by`` is MANDATORY — it tracks provenance so downstream
    consumers can distinguish an AI judgment from a deterministic
    fallback.  Allowed values:

    - ``"foundry"`` — classified by the Azure Foundry Agent (L5 model)
    - ``"prefilter"`` — intercepted by the deterministic prefilter
      (data too sparse for meaningful AI analysis)
    - ``"heuristic_fallback"`` — Foundry was unreachable or returned
      invalid output; verdict is a conservative guess, NOT an AI
      analysis
    """

    target_id: uuid.UUID
    classification: Classification
    confidence: float = 0.0
    produced_by: str = "foundry"
    brand: Optional[str] = None
    kit_family: Optional[str] = None
    rationale: Optional[str] = None
    final_url: Optional[str] = None
    exfil_endpoint: Optional[str] = None
