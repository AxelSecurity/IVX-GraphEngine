"""Tests for the OSINT filesystem cache."""

from __future__ import annotations

import time
from pathlib import Path

from graph_engine.osint.cache import cache_get, cache_set


class TestCacheSetGet:
    def test_set_and_get(self, tmp_path, monkeypatch):
        """Set + get: round-trip corretto."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        cache_set("test_provider", "example.com", {"data": 42})

        result = cache_get("test_provider", "example.com", ttl_seconds=3600)
        assert result is not None
        assert result["data"] == 42

    def test_missing_key_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        result = cache_get("test_provider", "nonexistent", ttl_seconds=3600)
        assert result is None

    def test_expired_ttl_returns_none(self, tmp_path, monkeypatch):
        """TTL scaduto → None."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        cache_set("test_provider", "expired.com", {"data": "old"})

        # Modifica il timestamp nel file per simulare scadenza
        cache_dir = tmp_path / "osint_cache" / "test_provider"
        cache_files = list(cache_dir.glob("*.json"))
        assert len(cache_files) == 1
        with open(cache_files[0], "r") as fh:
            import json
            envelope = json.load(fh)
        envelope["_cached_at"] = time.time() - 999_999  # molto vecchio
        with open(cache_files[0], "w") as fh:
            json.dump(envelope, fh)

        result = cache_get("test_provider", "expired.com", ttl_seconds=60)
        assert result is None

    def test_different_keys_dont_mix(self, tmp_path, monkeypatch):
        """Chiavi diverse → file diversi, non si mescolano."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        cache_set("p", "key_a", {"v": "a"})
        cache_set("p", "key_b", {"v": "b"})

        assert cache_get("p", "key_a", ttl_seconds=3600)["v"] == "a"
        assert cache_get("p", "key_b", ttl_seconds=3600)["v"] == "b"

    def test_different_providers_dont_mix(self, tmp_path, monkeypatch):
        """Provider diversi → directory diverse."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        cache_set("prov_a", "key", {"v": "a"})
        cache_set("prov_b", "key", {"v": "b"})

        assert cache_get("prov_a", "key", ttl_seconds=3600)["v"] == "a"
        assert cache_get("prov_b", "key", ttl_seconds=3600)["v"] == "b"

    def test_corrupted_json_returns_none(self, tmp_path, monkeypatch):
        """JSON corrotto → None (mai eccezione)."""
        monkeypatch.setattr(
            "graph_engine.osint.cache._CACHE_ROOT", tmp_path / "osint_cache"
        )
        from graph_engine.osint.cache import _hash_key
        cache_dir = tmp_path / "osint_cache" / "test_provider"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{_hash_key('bad')}.json"
        cache_file.write_text("{invalid json", encoding="utf-8")

        result = cache_get("test_provider", "bad", ttl_seconds=3600)
        assert result is None
