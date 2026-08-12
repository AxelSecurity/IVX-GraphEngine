"""Test per graph_engine.active.analyzer — orchestratore L3."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from graph_engine.active.analyzer import analyze


class TestAnalyzer:
    """Verifica l'orchestrazione parallela dei moduli L3."""

    async def test_all_modules_produce_results(self):
        """Integrazione con tutti i sotto-moduli mockati."""
        with patch(
            "graph_engine.active.analyzer.trace_redirect_chain",
            return_value={
                "hops": [{"status_code": 200, "url": "https://example.com"}],
                "final_url": "https://example.com",
                "hop_count": 1,
                "redirect_count": 0,
                "truncated": False,
            },
        ), patch(
            "graph_engine.active.analyzer.fetch_favicon_hash",
            return_value={"favicon_hash": 1234567890, "favicon_size_bytes": 1150},
        ), patch(
            "graph_engine.active.analyzer.compute_jarm",
            return_value="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
        ), patch(
            "graph_engine.active.analyzer.differential_fetch",
            return_value={
                "results": {
                    "desktop_chrome": {
                        "status_code": 200,
                        "final_url": "https://example.com",
                        "content_length": 5000,
                        "body_sha256": "abc123",
                    },
                    "bot_googlebot": {
                        "status_code": 200,
                        "final_url": "https://example.com",
                        "content_length": 5000,
                        "body_sha256": "abc123",
                    },
                },
                "profiles_compared": 2,
            },
        ):
            result = await analyze("https://example.com")

        # Deve contenere evidenze da tutti i moduli
        keys = [e["key"] for e in result["evidence"]]
        assert "redirect_hop_count" in keys
        assert "favicon_hash" in keys
        assert "jarm_fingerprint" in keys
        assert "differential_fetch_summary" in keys

        # Deve raccomandare un profilo
        assert "user_agent" in result["recommended_profile"]
        assert "headers" in result["recommended_profile"]

    async def test_one_module_failure_does_not_block_others(self):
        """Un fallimento (JARM) non impedisce agli altri di produrre risultati."""
        with patch(
            "graph_engine.active.analyzer.trace_redirect_chain",
            return_value={
                "hops": [{"status_code": 200, "url": "https://example.com"}],
                "final_url": "https://example.com",
                "hop_count": 1,
                "redirect_count": 0,
                "truncated": False,
            },
        ), patch(
            "graph_engine.active.analyzer.fetch_favicon_hash",
            return_value=None,  # favicon non trovato (non è un errore)
        ), patch(
            "graph_engine.active.analyzer.compute_jarm",
            side_effect=RuntimeError("JARM exploded"),  # errore inaspettato
        ), patch(
            "graph_engine.active.analyzer.differential_fetch",
            return_value={
                "results": {
                    "desktop_chrome": {
                        "status_code": 200,
                        "final_url": "https://example.com",
                        "content_length": 5000,
                        "body_sha256": "abc123",
                    },
                },
                "profiles_compared": 1,
            },
        ):
            result = await analyze("https://example.com")

        # Redirect chain deve aver prodotto evidenza
        redirect_ev = [e for e in result["evidence"] if e["key"] == "redirect_hop_count"]
        assert len(redirect_ev) == 1

        # JARM fallito → nessuna evidenza jarm_fingerprint
        jarm_ev = [e for e in result["evidence"] if e["key"] == "jarm_fingerprint"]
        assert len(jarm_ev) == 0

        # Differential fetch deve aver prodotto il summary
        diff_ev = [e for e in result["evidence"] if e["key"] == "differential_fetch_summary"]
        assert len(diff_ev) == 1

        # Il profilo raccomandato esiste anche con fallimenti
        assert "user_agent" in result["recommended_profile"]

    async def test_empty_hostname_returns_default(self):
        """URL senza hostname → evidenze vuote + profilo default."""
        result = await analyze("")

        assert result["evidence"] == []
        assert result["recommended_profile"]["user_agent"] is not None

    async def test_cloaking_detected_produces_evidence(self):
        """Cloaking rilevato → evidenza cloaking_detected."""
        with patch(
            "graph_engine.active.analyzer.trace_redirect_chain",
            return_value={
                "hops": [{"status_code": 200, "url": "https://evil.example.com"}],
                "final_url": "https://evil.example.com",
                "hop_count": 1,
                "redirect_count": 0,
                "truncated": False,
            },
        ), patch(
            "graph_engine.active.analyzer.fetch_favicon_hash",
            return_value=None,
        ), patch(
            "graph_engine.active.analyzer.compute_jarm",
            return_value=None,
        ), patch(
            "graph_engine.active.analyzer.differential_fetch",
            return_value={
                "results": {
                    "desktop_chrome": {
                        "status_code": 403,
                        "final_url": "https://evil.example.com/blocked",
                        "content_length": 50,
                        "body_sha256": "block_hash",
                    },
                    "bot_googlebot": {
                        "status_code": 200,
                        "final_url": "https://evil.example.com/real",
                        "content_length": 8000,
                        "body_sha256": "real_hash",
                    },
                },
                "profiles_compared": 2,
            },
        ):
            result = await analyze("https://evil.example.com")

        cloaking_ev = [e for e in result["evidence"] if e["key"] == "cloaking_detected"]
        assert len(cloaking_ev) == 1
        assert cloaking_ev[0]["value"]["divergent_profiles"]

    async def test_excessive_redirects_produce_evidence(self):
        """>= 5 redirect → evidenza excessive_redirects."""
        hops = []
        for i in range(6):
            hops.append({
                "status_code": 302,
                "url": f"https://example.com/hop{i}",
                "location": f"/hop{i+1}",
            })
        # Ultimo hop: 200 OK
        hops.append({
            "status_code": 200,
            "url": "https://example.com/final",
        })

        with patch(
            "graph_engine.active.analyzer.trace_redirect_chain",
            return_value={
                "hops": hops,
                "final_url": "https://example.com/final",
                "hop_count": 7,
                "redirect_count": 6,
                "truncated": False,
            },
        ), patch(
            "graph_engine.active.analyzer.fetch_favicon_hash",
            return_value=None,
        ), patch(
            "graph_engine.active.analyzer.compute_jarm",
            return_value=None,
        ), patch(
            "graph_engine.active.analyzer.differential_fetch",
            return_value={
                "results": {},
                "profiles_compared": 0,
            },
        ):
            result = await analyze("https://example.com")

        excessive_ev = [e for e in result["evidence"] if e["key"] == "excessive_redirects"]
        assert len(excessive_ev) == 1
        assert excessive_ev[0]["value"]["redirect_count"] == 6
