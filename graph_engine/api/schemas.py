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
# Response — GET /analyses (listing di tutte le sottomissioni)
# ---------------------------------------------------------------------------


class AnalysisListEntry(BaseModel):
    """Riga della lista sottomissioni — stesso formato di ``HistoryEntry``."""

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


class AnalysisListResponse(BaseModel):
    """Risposta paginata di GET /analyses — usata dalla dashboard."""

    total: int
    limit: int
    offset: int
    items: list[AnalysisListEntry]


# ---------------------------------------------------------------------------
# Request/Response — POST /analyses/delete (eliminazione definitiva)
# ---------------------------------------------------------------------------


class AnalysesDeleteRequest(BaseModel):
    """Body della POST /analyses/delete.

    ``ids`` non ha ``min_length``: il rifiuto della lista vuota è
    responsabilità della route (400 esplicito), non della validazione
    (422) — la risposta deve essere chiara, non un errore di validazione.
    """

    ids: list[str] = Field(
        max_length=200,
        description="UUID delle sottomissioni da eliminare definitivamente",
    )


class AnalysesDeleteResponse(BaseModel):
    """Risposta della POST /analyses/delete — stesso schema di
    ``repository.delete_targets``."""

    deleted_count: int
    not_found: list[str]


# ---------------------------------------------------------------------------
# Response — GET /analyses/{id}/trellix
# ---------------------------------------------------------------------------


class TrellixResult(BaseModel):
    """Contenuto del verdetto — letto da Trellix IVX come
    ``result.verdict`` / ``result.signature``."""

    verdict: str  # "safe" | "malicious"
    confidence: float
    signature: str
    recommended_action: str  # "allow" | "block"
    reason: str


class TrellixVerdictResponse(BaseModel):
    """Il JSON che la route Trellix IVX restituisce per questa analisi.

    Rigenerato on-demand da ``build_trellix_response`` (la stessa funzione
    della route ``GET /trellix/analyze``): ciò che la dashboard mostra è
    ciò che Trellix ha ricevuto o riceverebbe in questo momento.  Il
    payload è avvolto nella chiave ``result``: è il formato con cui
    l'integrazione Trellix IVX legge il verdetto.
    """

    result: TrellixResult


# ---------------------------------------------------------------------------
# Response — GET /health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Health check."""

    status: str  # "ok"
    running_jobs: int = 0


# ---------------------------------------------------------------------------
# Request/Response — GET/POST/DELETE /lists (whitelist/blacklist)
# ---------------------------------------------------------------------------


class ListEntry(BaseModel):
    """Una riga di una lista forzata (dominio o URL normalizzato)."""

    value: str
    list_type: str  # "whitelist" | "blacklist"
    note: Optional[str] = None
    added_by: Optional[str] = None
    added_at: str


class ListsResponse(BaseModel):
    """GET /lists — le due liste, ordinate per valore."""

    domains: list[ListEntry]
    urls: list[ListEntry]


class ListAddRequest(BaseModel):
    """Body della POST /lists."""

    kind: str = Field(description='"domain" o "url"')
    value: str = Field(min_length=1, max_length=2048)
    list_type: str = Field(description='"whitelist" o "blacklist"')
    note: Optional[str] = None


class ListAddResponse(BaseModel):
    """Risposta della POST /lists — riporta il valore normalizzato salvato."""

    ok: bool = True
    kind: str
    value: str  # valore normalizzato
    list_type: str


class ListRemoveRequest(BaseModel):
    """Body della DELETE /lists."""

    kind: str
    value: str


class ListRemoveResponse(BaseModel):
    """Risposta della DELETE /lists."""

    ok: bool = True
    removed: bool


# ---------------------------------------------------------------------------
# Request/Response — autenticazione (/auth/*)
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Body della POST /auth/login."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AuthUserResponse(BaseModel):
    """Utente autenticato o elencato (mai l'hash della password)."""

    username: str
    role: str  # "admin" | "operator"
    created_at: Optional[str] = None  # presente solo nella lista (GET /auth/users)


class LoginResponse(AuthUserResponse):
    """Risposta della POST /auth/login (setta anche il cookie di sessione)."""

    ok: bool = True


class LogoutResponse(BaseModel):
    """Risposta della POST /auth/logout."""

    ok: bool = True


class UserCreateRequest(BaseModel):
    """Body della POST /auth/users (solo admin)."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = "operator"


class UserCreateResponse(AuthUserResponse):
    """Risposta della POST /auth/users."""

    ok: bool = True


class UsersListResponse(BaseModel):
    """Risposta della GET /auth/users (solo admin)."""

    users: list[AuthUserResponse]


class UserDeleteResponse(BaseModel):
    """Risposta della DELETE /auth/users/{username} (solo admin)."""

    ok: bool = True
    removed: bool


class UserUpdateRequest(BaseModel):
    """Body della PATCH /auth/users/{username} (solo admin).

    Entrambi i campi sono opzionali: si cambia solo ciò che viene
    valorizzato.  Cambiare la password revoca le sessioni attive
    dell'utente (anche le proprie).
    """

    password: Optional[str] = Field(default=None, min_length=8, max_length=256)
    role: Optional[str] = None  # "admin" | "operator"


class UserUpdateResponse(AuthUserResponse):
    """Risposta della PATCH /auth/users/{username} — ruolo allo stato finale."""

    ok: bool = True
