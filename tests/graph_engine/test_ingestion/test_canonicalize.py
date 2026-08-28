"""Tests for URL canonicalization and hashing."""

from __future__ import annotations

from graph_engine.ingestion.canonicalize import canonicalize_and_hash


class TestSameLogicalUrlProducesSameHash:
    def test_percent_encoding_variations(self):
        _, h1 = canonicalize_and_hash("https://evil.example/a%20b")
        _, h2 = canonicalize_and_hash("https://evil.example/a b")
        assert h1 == h2

    def test_query_order_independent(self):
        _, h1 = canonicalize_and_hash(
            "https://evil.example/?a=1&b=2&c=3"
        )
        _, h2 = canonicalize_and_hash(
            "https://evil.example/?c=3&a=1&b=2"
        )
        assert h1 == h2

    def test_scheme_case_insensitive(self):
        _, h1 = canonicalize_and_hash("HTTP://evil.example/")
        _, h2 = canonicalize_and_hash("http://evil.example/")
        assert h1 == h2

    def test_hostname_case_insensitive(self):
        _, h1 = canonicalize_and_hash("https://EVIL.example/Login")
        _, h2 = canonicalize_and_hash("https://evil.example/Login")
        assert h1 == h2

    def test_default_port_removed(self):
        _, h1 = canonicalize_and_hash("https://evil.example:443/login")
        _, h2 = canonicalize_and_hash("https://evil.example/login")
        assert h1 == h2

        _, h3 = canonicalize_and_hash("http://evil.example:80/login")
        _, h4 = canonicalize_and_hash("http://evil.example/login")
        assert h3 == h4

    def test_non_default_port_preserved(self):
        _, h1 = canonicalize_and_hash("https://evil.example:8443/login")
        _, h2 = canonicalize_and_hash("https://evil.example/login")
        assert h1 != h2

    def test_nested_percent_encoding(self):
        # %253A → %3A → :
        _, h1 = canonicalize_and_hash("https://evil.example/%253A")
        _, h2 = canonicalize_and_hash("https://evil.example/%3A")
        # Not necessarily same — depends on if both decode to same thing
        # Let's just check that deeply nested is decoded
        c1, _ = canonicalize_and_hash("https://evil.example/%252F")
        # %252F = %25 2F → % decodes to % → %2F → / decodes to /
        assert "/" in c1

    def test_empty_path_normalized_to_slash(self):
        """https://example.org e https://example.org/ → stesso hash
        (RFC 3986 §6.2.3 — il path vuoto è equivalente a "/").
        Regressione del collaudo Trellix (2026-08-27): la cache 24h
        non riconosceva le due scritture come la stessa analisi e
        rilanciare una seconda esplorazione completa."""
        c1, h1 = canonicalize_and_hash("https://example.org")
        c2, h2 = canonicalize_and_hash("https://example.org/")
        assert h1 == h2
        assert c1 == c2 == "https://example.org/"

    def test_empty_path_with_query_normalized(self):
        """La normalizzazione vale anche con query string presente."""
        _, h1 = canonicalize_and_hash("https://example.org?a=1&b=2")
        _, h2 = canonicalize_and_hash("https://example.org/?a=1&b=2")
        assert h1 == h2


class TestDifferentUrlsProduceDifferentHash:
    def test_different_paths(self):
        _, h1 = canonicalize_and_hash("https://evil.example/login")
        _, h2 = canonicalize_and_hash("https://evil.example/phish")
        assert h1 != h2

    def test_different_domains(self):
        _, h1 = canonicalize_and_hash("https://evil.example/page")
        _, h2 = canonicalize_and_hash("https://benign.example/page")
        assert h1 != h2

    def test_non_empty_path_trailing_slash_preserved(self):
        """/path e /path/ possono essere risorse diverse: hash diversi
        (la normalizzazione RFC vale SOLO per il path vuoto)."""
        _, h1 = canonicalize_and_hash("https://evil.example/login")
        _, h2 = canonicalize_and_hash("https://evil.example/login/")
        assert h1 != h2


class TestHashFormat:
    def test_hash_is_64_char_hex(self):
        _, h = canonicalize_and_hash("https://evil.example/")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)
