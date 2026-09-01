"""Route di autenticazione — login/logout/me e gestione utenti.

La protezione delle altre route è affidata al middleware di sessione
in ``app.create_app``: qui ``/auth/me`` e le route admin si limitano a
leggere ``request.state.user`` (popolato dal middleware) e a imporre il
ruolo ``admin`` dove serve.

``POST /auth/login`` e ``POST /auth/logout`` sono esenti dal middleware:
il login deve restare raggiungibile anonimo, il logout deve sempre
poter ripulire il cookie (anche a sessione scaduta).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from graph_engine.api import auth
from graph_engine.api.schemas import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    UserCreateRequest,
    UserCreateResponse,
    UserDeleteResponse,
    UserUpdateRequest,
    UserUpdateResponse,
    UsersListResponse,
)
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api.auth_routes")


def _require_admin(request: Request) -> dict:
    """Restituisce la sessione solo se appartiene a un admin, altrimenti 403.

    Il middleware ha già garantito che la sessione esista (401 altrimenti):
    qui si controlla il solo ruolo.
    """
    user = getattr(request.state, "user", None)
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Richiede ruolo admin")
    return user


def build_auth_router(
    db_path: str = DEFAULT_DB_PATH,
) -> APIRouter:
    """Costruisce il router /auth con dipendenze iniettate."""
    router = APIRouter(prefix="/auth", tags=["auth"])

    # ── POST /auth/login ──────────────────────────────────────────────

    @router.post("/login", response_model=LoginResponse)
    async def login(payload: LoginRequest):
        """Autentica con username/password e setta il cookie di sessione."""
        user = await auth.authenticate(
            db_path, payload.username, payload.password
        )
        if user is None:
            raise HTTPException(status_code=401, detail="Credenziali non valide")

        token = auth.create_session(user["username"], user["role"])
        logger.info("Login riuscito: %s (role=%s)", user["username"], user["role"])
        response = JSONResponse(
            LoginResponse(
                username=user["username"], role=user["role"]
            ).model_dump()
        )
        response.set_cookie(
            auth.SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=auth.SESSION_TTL_S,
            path="/",
        )
        return response

    # ── POST /auth/logout ─────────────────────────────────────────────

    @router.post("/logout", response_model=LogoutResponse)
    async def logout(request: Request):
        """Invalida la sessione corrente e cancella il cookie."""
        token = auth.read_session_cookie(request)
        auth.delete_session(token)
        response = JSONResponse(LogoutResponse().model_dump())
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return response

    # ── GET /auth/me ──────────────────────────────────────────────────

    @router.get("/me", response_model=LoginResponse)
    async def me(request: Request):
        """Identità dell'utente autenticato (dal middleware, 401 se anonimo)."""
        user = request.state.user
        return LoginResponse(username=user["username"], role=user["role"])

    # ── GET /auth/users (solo admin) ──────────────────────────────────

    @router.get("/users", response_model=UsersListResponse)
    async def list_users(request: Request):
        """Elenco degli utenti — solo admin."""
        _require_admin(request)
        users = await auth.list_users(db_path)
        return UsersListResponse(
            users=[
                {
                    "username": u["username"],
                    "role": u["role"],
                    "created_at": u["created_at"],
                }
                for u in users
            ]
        )

    # ── POST /auth/users (solo admin) ─────────────────────────────────

    @router.post("/users", response_model=UserCreateResponse, status_code=201)
    async def create_user(payload: UserCreateRequest, request: Request):
        """Crea un utente — solo admin."""
        _require_admin(request)
        try:
            await auth.create_user(
                db_path, payload.username, payload.password, payload.role
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return UserCreateResponse(username=payload.username.strip(), role=payload.role)

    # ── DELETE /auth/users/{username} (solo admin) ────────────────────

    @router.delete("/users/{username}", response_model=UserDeleteResponse)
    async def delete_user(username: str, request: Request):
        """Cancella un utente (e le sue sessioni) — solo admin.

        Protezioni (2026-09-01, pagina Gestione utenti): un admin non può
        cancellare il proprio account né eliminare l'ultimo admin rimasto
        (altrimenti la gestione utenti resterebbe senza accesso).
        """
        me = _require_admin(request)
        if username == me["username"]:
            raise HTTPException(
                status_code=409, detail="Non puoi eliminare il tuo account"
            )
        await _ensure_not_last_admin(db_path, username)
        removed = await auth.delete_user(db_path, username)
        return UserDeleteResponse(removed=removed)

    # ── PATCH /auth/users/{username} (solo admin) ─────────────────────

    @router.patch("/users/{username}", response_model=UserUpdateResponse)
    async def update_user(username: str, payload: UserUpdateRequest, request: Request):
        """Cambia password e/o ruolo di un utente — solo admin.

        Se la password dell'utente corrente viene cambiata, la sua
        sessione viene revocata (come le altre): dovrà rifare il login.
        L'ultimo admin non può essere degradato a operator.
        """
        _require_admin(request)
        if payload.role == "operator":
            await _ensure_not_last_admin(db_path, username)
        try:
            updated = await auth.update_user(
                db_path,
                username,
                password=payload.password,
                role=payload.role,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if updated is None:
            raise HTTPException(status_code=404, detail="Utente non trovato")
        return UserUpdateResponse(username=username, role=updated["role"])

    return router


async def _ensure_not_last_admin(db_path: str, username: str) -> None:
    """409 se ``username`` è l'ultimo admin rimasto.

    Impedisce di eliminare o degradare l'unico amministratore: senza
    admin nessuno potrebbe più gestire gli utenti (e il bootstrap non
    ne crea di nuovi a tabella non vuota).
    """
    users = await auth.list_users(db_path)
    target = next((u for u in users if u["username"] == username), None)
    if target is None or target["role"] != "admin":
        return
    admin_count = sum(1 for u in users if u["role"] == "admin")
    if admin_count <= 1:
        raise HTTPException(
            status_code=409,
            detail="Impossibile: è l'ultimo amministratore rimasto",
        )
