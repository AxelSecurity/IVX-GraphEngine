"""Test per allowlist/blacklist — CRUD e matching su dominio registrabile."""

from __future__ import annotations

import pytest

from graph_engine.api.allowlist import add_entry, check_domain, remove_entry


class TestAllowlist:
    """Test CRUD e matching della tabella allowlist_blacklist."""

    async def test_add_and_check_whitelist_exact(self, tmp_path):
        """Dominio esatto: aggiunto 'example.com', matcha 'example.com'."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "whitelist", note="Test", db_path=db)

        result = await check_domain("example.com", db_path=db)
        assert result is not None
        assert result["list_type"] == "whitelist"
        assert result["note"] == "Test"

    async def test_subdomain_matches_registrable(self, tmp_path):
        """Sottodominio: aggiunto 'example.com', matcha 'login.example.com'."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "blacklist", db_path=db)

        result = await check_domain("login.example.com", db_path=db)
        assert result is not None
        assert result["list_type"] == "blacklist"

    async def test_different_domain_no_match(self, tmp_path):
        """Dominio diverso: aggiunto 'example.com', 'evil.com' non matcha."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "blacklist", db_path=db)

        result = await check_domain("evil.com", db_path=db)
        assert result is None

    async def test_url_input_normalized(self, tmp_path):
        """URL intero: 'https://login.example.com/path' → match su example.com."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "whitelist", db_path=db)

        result = await check_domain(
            "https://login.example.com/path?q=1", db_path=db,
        )
        assert result is not None
        assert result["list_type"] == "whitelist"

    async def test_remove_entry(self, tmp_path):
        """remove_entry rimuove e check_domain restituisce None."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "blacklist", db_path=db)

        removed = await remove_entry("example.com", db_path=db)
        assert removed is True

        result = await check_domain("example.com", db_path=db)
        assert result is None

    async def test_remove_nonexistent_returns_false(self, tmp_path):
        """Rimozione entry inesistente → False."""
        db = str(tmp_path / "test.db")
        removed = await remove_entry("nonexistent.com", db_path=db)
        assert removed is False

    async def test_add_duplicate_idempotent(self, tmp_path):
        """Due INSERT consecutive sullo stesso dominio → idempotente (INSERT OR REPLACE)."""
        db = str(tmp_path / "test.db")
        await add_entry("example.com", "whitelist", note="first", db_path=db)
        await add_entry("example.com", "blacklist", note="second", db_path=db)

        result = await check_domain("example.com", db_path=db)
        assert result is not None
        # L'ultima INSERT OR REPLACE vince
        assert result["list_type"] == "blacklist"
        assert result["note"] == "second"

    async def test_invalid_list_type_raises(self, tmp_path):
        """list_type non valido → ValueError."""
        db = str(tmp_path / "test.db")
        with pytest.raises(ValueError, match="list_type"):
            await add_entry("example.com", "invalid", db_path=db)

    async def test_case_insensitive_and_trailing_dot(self, tmp_path):
        """Dominio con maiuscole e dot finale → normalizzato."""
        db = str(tmp_path / "test.db")
        await add_entry("Example.COM.", "whitelist", db_path=db)
        result = await check_domain("EXAMPLE.COM", db_path=db)
        assert result is not None
        assert result["list_type"] == "whitelist"
