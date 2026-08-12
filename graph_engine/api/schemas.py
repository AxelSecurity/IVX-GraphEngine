"""Pydantic request/response models for the HTTP API.

Questi modelli sono **distinti** da quelli di dominio (``graph_engine.models``):
- I modelli di dominio sono la fonte di verità per la logica di business
- Questi modelli sono il contratto HTTP — possono evolversi indipendentemente
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    Evidence,
    State,
    TargetStatus,
    Transition,
    Verdict,
)


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


class BudgetRequest(BaseModel):
    """Parametri di budget opzionali per l'esplorazione."""

    max_depth: int = Field(default=6, ge=1, le=20)
    max_nodes: int = Field(default=40, ge=1, le=200)
    timeout_s: int = Field(default=180, ge=10, le=3600)


class AnalysisCreateRequest(BaseModel):
    """Body della POST /analyses.

    ``url`` è ``str`` (non ``HttpUrl``) perché la pipeline L0 gestisce
    formati defanged (``hxxp://...``) che ``HttpUrl`` rifiuterebbe.
    """

    url: str = Field(
        min_length=1,
        max_length=2048,
        description="Raw URL — può essere defanged/wrapped",
    )
    budget: Optional[BudgetRequest] = None
    classify: bool = True


# ---------------------------------------------------------------------------
# Response — POST /analyses
# ---------------------------------------------------------------------------


class AnalysisCreatedResponse(BaseModel):
    """Risposta 202 Accepted — il job è stato accodato."""

    id: str
    status: str  # "queued"
    input_url: str


# ---------------------------------------------------------------------------
# Response — GET /analyses/{id} (summary)
# ---------------------------------------------------------------------------


class TargetSummary(BaseModel):
    """Vista compatta di AnalysisTarget per il summary endpoint."""

    id: str
    input_url: str
    canonical_url: Optional[str] = None
    url_hash: Optional[str] = None
    final_url: Optional[str] = None
    status: str
    root_state_id: Optional[str] = None
    created_at: datetime


class VerdictSummary(BaseModel):
    """Vista compatta di Verdict."""

    classification: Optional[str] = None
    confidence: float = 0.0
    produced_by: Optional[str] = None
    brand: Optional[str] = None
    kit_family: Optional[str] = None
    rationale: Optional[str] = None


class AnalysisSummaryResponse(BaseModel):
    """GET /analyses/{id} — target + verdict + conteggi, senza il grafo."""

    target: TargetSummary
    verdict: Optional[VerdictSummary] = None
    num_states: int = 0
    num_transitions: int = 0
    num_evidence: int = 0


# ---------------------------------------------------------------------------
# Response — GET /analyses/{id}/graph
# ---------------------------------------------------------------------------


class AnalysisGraphResponse(BaseModel):
    """GET /analyses/{id}/graph — grafo completo."""

    target: TargetSummary
    states: list[dict]
    transitions: list[dict]
    evidence: list[dict]
    verdict: Optional[VerdictSummary] = None


# ---------------------------------------------------------------------------
# Response — GET /analyses/{id}/artifacts
# ---------------------------------------------------------------------------


class ArtifactFile(BaseModel):
    """Un file artefatto con path relativo e dimensione."""

    path: str
    name: str
    size_bytes: int


class ArtifactListing(BaseModel):
    """Listing degli artefatti per un target."""

    target_id: str
    count: int
    files: list[ArtifactFile]


# ---------------------------------------------------------------------------
# Response — GET /analyses/history
# ---------------------------------------------------------------------------


class HistoryEntry(BaseModel):
    """Riga del summary storico restituito da ``get_history_for_url_hash``."""

    id: str
    input_url: str
    final_url: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None
    classification: Optional[str] = None
    confidence: Optional[float] = None
    brand: Optional[str] = None
    kit_family: Optional[str] = None
    rationale: Optional[str] = None
    num_states: int = 0
    num_transitions: int = 0


class HistoryResponse(BaseModel):
    """Risposta dell'endpoint history."""

    url: Optional[str] = None
    url_hash: str
    history: list[HistoryEntry]


# ---------------------------------------------------------------------------
# Response — GET /health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Health check."""

    status: str  # "ok"
    running_jobs: int = 0
