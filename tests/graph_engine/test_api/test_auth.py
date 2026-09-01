"""Test dell'autenticazione dashboard/API (middleware di sessione).

Copre il contratto deciso il 2026-09-01: il login multi-utente su
SQLite protegge la UI e TUTTE le API REST, tranne /health, /auth/login,
/auth/logout, la route Trellix (API key propria) e il codice statico
della dashboard.  Le sessioni vivono in un cookie HttpOnly in memoria.

Le fixture ``client``/``anon_client`` vengono dal conftest: la prima è
già autenticata come admin, la seconda non ha cookie di sessione.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from graph_engine.api import auth as auth_mod
from graph_engine.config import settings


class TestMiddleware:
    """Il middleware di sessione protegge le route, con le eccezioni pattuite."""

    async def test_analyses_requires_session(self, anon_client):
        res = await anon_client.get("/analyses")
        assert res.status_code == 401
        assert res.json()["detail"] == "Autenticazione richiesta"

    async def test_lists_requires_session(self, anon_client):
        res = await anon_client.get("/lists")
        assert res.status_code == 401

    async def test_health_stays_open(self, anon_client):
        res = await anon_client.get("/health")
        assert res.status_code == 200

    async def test_dashboard_static_stays_open(self, anon_client):
        """La SPA deve caricarsi anonima: è lei a mostrare il login."""
        res = await anon_client.get("/dashboard/")
        assert res.status_code == 200
        assert "html" in res.headers["content-type"]

    async def test_trellix_route_uses_own_key_not_session(self, anon_client):
        """Senza API key configurata risponde 503 (configurazione), non 401
        di sessione — prova che il middleware la lascia passare."""
        res = await anon_client.get("/trellix/analyze?url=https://example.com")
        assert res.status_code == 503

    async def test_authed_client_passes(self, client):
        res = await client.get("/analyses")
        assert res.status_code == 200

    async def test_openapi_protected(self, anon_client):
        """La documentazione automatica è parte dell'API → protetta."""
        res = await anon_client.get("/openapi.json")
        assert res.status_code == 401


class TestLoginLogout:
    async def test_wrong_password_returns_401(self, anon_client):
        res = await anon_client.post(
            "/auth/login",
            json={"username": "admin", "password": "sbagliata"},
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "Credenziali non valide"

    async def test_unknown_user_returns_401(self, anon_client):
        res = await anon_client.post(
            "/auth/login",
            json={"username": "inesistente", "password": "qualsiasi"},
        )
        assert res.status_code == 401

    async def test_login_sets_httponly_cookie(self, app, anon_client):
        # L'anon_client non fa bootstrap: crea l'admin e fissa una
        # password nota (quella casuale del bootstrap non è leggibile)
        await auth_mod.ensure_bootstrap_admin(app.state.db_path)
        await auth_mod.set_password(app.state.db_path, "admin", "password-di-test")
        res = await anon_client.post(
            "/auth/login",
            json={"username": "admin", "password": "password-di-test"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"
        set_cookie = res.headers["set-cookie"]
        assert "session=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "samesite=lax" in set_cookie.lower()

    async def test_me_with_session(self, client):
        res = await client.get("/auth/me")
        assert res.status_code == 200
        assert res.json()["username"] == "admin"
        assert res.json()["role"] == "admin"

    async def test_me_without_session_returns_401(self, anon_client):
        res = await anon_client.get("/auth/me")
        assert res.status_code == 401

    async def test_logout_invalidates_session(self, client):
        res = await client.post("/auth/logout")
        assert res.status_code == 200
        # Dopo il logout il cookie di sessione non vale più
        res2 = await client.get("/auth/me")
        assert res2.status_code == 401

    async def test_logout_without_session_ok(self, anon_client):
        """Il logout è esente dal middleware: ripulisce comunque il cookie."""
        res = await anon_client.post("/auth/logout")
        assert res.status_code == 200


class TestUserManagement:
    async def test_list_users_as_admin(self, client):
        res = await client.get("/auth/users")
        assert res.status_code == 200
        usernames = [u["username"] for u in res.json()["users"]]
        assert "admin" in usernames

    async def test_create_and_login_as_operator(self, app, client, anon_client):
        res = await client.post(
            "/auth/users",
            json={"username": "oper", "password": "password-oper", "role": "operator"},
        )
        assert res.status_code == 201
        assert res.json()["role"] == "operator"

        # Il nuovo utente può fare login
        res2 = await anon_client.post(
            "/auth/login",
            json={"username": "oper", "password": "password-oper"},
        )
        assert res2.status_code == 200
        assert res2.json()["role"] == "operator"

    async def test_create_duplicate_returns_409(self, client):
        res = await client.post(
            "/auth/users",
            json={"username": "admin", "password": "password-altra", "role": "admin"},
        )
        assert res.status_code == 409

    async def test_delete_user(self, app, client, anon_client):
        await client.post(
            "/auth/users",
            json={"username": "temp", "password": "password-temp", "role": "operator"},
        )
        res = await client.request("DELETE", "/auth/users/temp")
        assert res.status_code == 200
        assert res.json()["removed"] is True

        # L'utente cancellato non può più fare login
        res2 = await anon_client.post(
            "/auth/login",
            json={"username": "temp", "password": "password-temp"},
        )
        assert res2.status_code == 401

    async def test_operator_cannot_manage_users(self, app, client, anon_client):
        await client.post(
            "/auth/users",
            json={"username": "oper", "password": "password-oper", "role": "operator"},
        )
        token = auth_mod.create_session("oper", "operator")
        # Sessione operator: GET/POST/DELETE /auth/users → 403
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            cookies={"session": token},
        ) as op_client:
            assert (await op_client.get("/auth/users")).status_code == 403
            assert (
                await op_client.post(
                    "/auth/users",
                    json={"username": "x", "password": "password-x"},
                )
            ).status_code == 403
            assert (
                await op_client.request("DELETE", "/auth/users/admin")
            ).status_code == 403

        # Le route normali restano accessibili all'operator
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            cookies={"session": token},
        ) as op_client:
            assert (await op_client.get("/analyses")).status_code == 200


class TestPasswordHashing:
    def test_hash_roundtrip_and_format(self):
        hashed = auth_mod.hash_password("password-segreta")
        assert hashed.startswith("pbkdf2_sha256$")
        assert auth_mod.verify_password("password-segreta", hashed) is True
        assert auth_mod.verify_password("password-errata", hashed) is False

    def test_malformed_hash_returns_false(self):
        assert auth_mod.verify_password("x", "formato-non-valido") is False
        assert auth_mod.verify_password("x", "algo_sconosciuto$1$00$00") is False

    def test_different_salts_give_different_hashes(self):
        a = auth_mod.hash_password("stessa-password")
        b = auth_mod.hash_password("stessa-password")
        assert a != b
        assert auth_mod.verify_password("stessa-password", a) is True
        assert auth_mod.verify_password("stessa-password", b) is True


class TestSessions:
    def test_session_lifecycle(self):
        token = auth_mod.create_session("utente", "operator")
        session = auth_mod.get_session(token)
        assert session["username"] == "utente"
        assert session["role"] == "operator"

        auth_mod.delete_session(token)
        assert auth_mod.get_session(token) is None

    def test_expired_session_returns_none(self, monkeypatch):
        import time as _time

        token = auth_mod.create_session("utente", "operator")
        # Simula la scadenza: sposta expires_at nel passato
        auth_mod._sessions[token]["expires_at"] = _time.time() - 1
        assert auth_mod.get_session(token) is None
        assert token not in auth_mod._sessions  # ripulita

    def test_revoke_user_sessions(self):
        t1 = auth_mod.create_session("utente", "operator")
        t2 = auth_mod.create_session("utente", "operator")
        t3 = auth_mod.create_session("altro", "admin")
        auth_mod.revoke_user_sessions("utente")
        assert auth_mod.get_session(t1) is None
        assert auth_mod.get_session(t2) is None
        assert auth_mod.get_session(t3) is not None

    def test_get_unknown_token_returns_none(self):
        assert auth_mod.get_session("token-inesistente") is None
        assert auth_mod.get_session(None) is None


class TestBootstrapAdmin:
    async def test_bootstrap_creates_admin_once(self, app):
        await auth_mod.ensure_bootstrap_admin(app.state.db_path)
        users = await auth_mod.list_users(app.state.db_path)
        assert len(users) == 1
        assert users[0]["username"] == "admin"
        assert users[0]["role"] == "admin"

        # Idempotente: una seconda chiamata non crea altri utenti
        await auth_mod.ensure_bootstrap_admin(app.state.db_path)
        users = await auth_mod.list_users(app.state.db_path)
        assert len(users) == 1

    async def test_bootstrap_uses_env_credentials(self, app, monkeypatch):
        monkeypatch.setattr(settings, "dashboard_admin_user", "capo")
        monkeypatch.setattr(settings, "dashboard_admin_password", "password-capo")
        await auth_mod.ensure_bootstrap_admin(app.state.db_path)
        user = await auth_mod.authenticate(app.state.db_path, "capo", "password-capo")
        assert user is not None
        assert user["role"] == "admin"
