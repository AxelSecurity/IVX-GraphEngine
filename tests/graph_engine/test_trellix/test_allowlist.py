"""Test per allowlist/blacklist — CRUD e matching su dominio registrabile e URL."""

from __future__ import annotations

import pytest

from graph_engine.api.allowlist import (
    add_entry,
    add_url_entry,
    check_domain,
    check_url,
    check_url_and_domain,
    list_entries,
    remove_entry,
    remove_url_entry,
)


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


class TestAllowlistUrl:
    """Test CRUD e matching della tabella allowlist_blacklist_url.

    Semantica (decisione utente 2026-09-01): il confronto avviene sulla
    URL normalizzata L0 SENZA query e frammento — scheme+host+path.
    """

    async def test_url_match_exact(self, tmp_path):
        """URL esatta: aggiunta 'https://site.it/login', matcha sé stessa."""
        db = str(tmp_path / "test.db")
        await add_url_entry("https://site.it/login", "whitelist", note="T", db_path=db)

        result = await check_url("https://site.it/login", db_path=db)
        assert result is not None
        assert result["list_type"] == "whitelist"
        assert result["note"] == "T"
        assert result["matched"] == "url"
        assert result["match_key"] == "https://site.it/login"

    async def test_url_query_and_fragment_ignored(self, tmp_path):
        """Query e frammento NON contano: aggiunta con '?sid=abc#top'
        matcha varianti con query/frammento diversi (o assenti)."""
        db = str(tmp_path / "test.db")
        await add_url_entry(
            "https://site.it/login?sid=abc#top", "blacklist", db_path=db,
        )

        for probe in (
            "https://site.it/login",
            "https://site.it/login?other=1",
            "https://site.it/login#frag",
        ):
            result = await check_url(probe, db_path=db)
            assert result is not None, f"{probe} doveva matchare"
            assert result["list_type"] == "blacklist"
            assert result["match_key"] == "https://site.it/login"

    async def test_url_host_case_and_default_port_normalized(self, tmp_path):
        """Host con maiuscole e porta default → normalizzati dalla L0."""
        db = str(tmp_path / "test.db")
        await add_url_entry("HTTPS://Sito.IT:443/Login", "whitelist", db_path=db)

        result = await check_url("https://sito.it/Login", db_path=db)
        assert result is not None
        assert result["list_type"] == "whitelist"
        assert result["match_key"] == "https://sito.it/Login"

    async def test_url_different_path_no_match(self, tmp_path):
        """Path diverso → nessun match (il confronto è sul path, non solo host)."""
        db = str(tmp_path / "test.db")
        await add_url_entry("https://site.it/a", "blacklist", db_path=db)

        assert await check_url("https://site.it/b", db_path=db) is None

    async def test_url_invalid_scheme_raises(self, tmp_path):
        """Scheme non http/https → ValueError (mai salvata o cercata)."""
        db = str(tmp_path / "test.db")
        with pytest.raises(ValueError):
            await add_url_entry("ftp://site.it/x", "blacklist", db_path=db)
        with pytest.raises(ValueError):
            await check_url("ftp://site.it/x", db_path=db)

    async def test_add_url_returns_normalized(self, tmp_path):
        """add_url_entry restituisce la URL normalizzata effettivamente salvata."""
        db = str(tmp_path / "test.db")
        normalized = await add_url_entry(
            "https://site.it/login?sid=1", "whitelist", db_path=db,
        )
        assert normalized == "https://site.it/login"

    async def test_remove_url_entry(self, tmp_path):
        """remove_url_entry rimuove; la seconda rimozione → False."""
        db = str(tmp_path / "test.db")
        await add_url_entry("https://site.it/login", "blacklist", db_path=db)

        assert await remove_url_entry("https://site.it/login?x=1", db_path=db) is True
        assert await check_url("https://site.it/login", db_path=db) is None
        assert await remove_url_entry("https://site.it/login", db_path=db) is False

    async def test_url_list_idempotent_replace(self, tmp_path):
        """Due INSERT sullo stesso valore normalizzato → l'ultima vince."""
        db = str(tmp_path / "test.db")
        await add_url_entry("https://site.it/a", "whitelist", note="one", db_path=db)
        await add_url_entry("https://site.it/a?x=1", "blacklist", note="two", db_path=db)

        result = await check_url("https://site.it/a", db_path=db)
        assert result["list_type"] == "blacklist"
        assert result["note"] == "two"

    async def test_list_entries_both_tables(self, tmp_path):
        """list_entries restituisce entrambe le liste con valori normalizzati."""
        db = str(tmp_path / "test.db")
        await add_entry("site.it", "whitelist", db_path=db)
        await add_url_entry("https://site.it/login?sid=1", "blacklist", db_path=db)

        result = await list_entries(db_path=db)
        assert len(result["domains"]) == 1
        assert result["domains"][0]["value"] == "site.it"
        assert result["domains"][0]["list_type"] == "whitelist"
        assert len(result["urls"]) == 1
        assert result["urls"][0]["value"] == "https://site.it/login"
        assert result["urls"][0]["list_type"] == "blacklist"


class TestCheckUrlAndDomain:
    """Priorità combinata (decisione utente 2026-09-01): URL > dominio."""

    async def test_url_wins_over_domain(self, tmp_path):
        """Dominio in blacklist ma URL specifica in whitelist → vince la URL.

        Il match URL è sul path esatto (query ignorata): un path diverso
        NON è coperto dall'entry URL e ricade sul dominio.
        """
        db = str(tmp_path / "test.db")
        await add_entry("site.it", "blacklist", db_path=db)
        await add_url_entry("https://site.it/trusted", "whitelist", db_path=db)

        result = await check_url_and_domain(
            "https://site.it/trusted?q=1", db_path=db,
        )
        assert result["list_type"] == "whitelist"
        assert result["matched"] == "url"
        assert result["match_key"] == "https://site.it/trusted"

        # Path diverso → nessun match URL → vince il dominio (blacklist)
        fallback = await check_url_and_domain(
            "https://site.it/trusted/p", db_path=db,
        )
        assert fallback["list_type"] == "blacklist"
        assert fallback["matched"] == "domain"

    async def test_domain_fallback_when_no_url_match(self, tmp_path):
        """Nessun match URL → si passa al dominio registrabile."""
        db = str(tmp_path / "test.db")
        await add_entry("site.it", "blacklist", db_path=db)

        result = await check_url_and_domain(
            "https://login.site.it/other", db_path=db,
        )
        assert result["list_type"] == "blacklist"
        assert result["matched"] == "domain"
        assert result["match_key"] == "site.it"

    async def test_no_match_returns_none(self, tmp_path):
        """Nessuna entry in nessuna lista → None."""
        db = str(tmp_path / "test.db")
        result = await check_url_and_domain("https://site.it/x", db_path=db)
        assert result is None
