"""Test per graph_engine.active.differential_fetch — cloaking detection."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from graph_engine.active.differential_fetch import (
    PROFILES,
    _make_client_for_profile,
    detect_cloaking,
    differential_fetch,
    recommend_profile,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_response(status_code=200, final_url="https://example.com/page",
                   body=b"same content", content_length=None):
    """Costruisce un mock di risposta httpx."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.url = final_url
    body_bytes = body if isinstance(body, bytes) else body.encode()
    resp.content = body_bytes
    if content_length is not None:
        resp.headers = {"content-length": str(content_length)}
    return resp


def _make_fake_client_factory(responses: dict[str, MagicMock]):
    """Factory che restituisce client mockati con risposte predefinite per profilo."""

    def factory(profile: dict) -> httpx.AsyncClient:
        from unittest.mock import AsyncMock, MagicMock

        # Identifica il profilo dal suo user_agent
        ua = profile["user_agent"]
        client = AsyncMock(spec=httpx.AsyncClient)

        # Trova la risposta corrispondente
        for name, prof in PROFILES.items():
            if prof["user_agent"] == ua and name in responses:
                client.get = AsyncMock(return_value=responses[name])
                break
        else:
            # Default: 200 same content
            client.get = AsyncMock(return_value=_fake_response())

        # Mock context manager
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)

        return client

    return factory


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


class TestDetectCloaking:
    """Rilevamento cloaking tra profili."""

    def test_identical_responses_no_cloaking(self):
        """Tutti i profili ricevono la stessa risposta → no cloaking."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "mobile_safari": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "bot_googlebot": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
        }

        cloaking = detect_cloaking(results)
        assert cloaking["cloaking_detected"] is False
        assert cloaking["divergent_profiles"] == []

    def test_divergent_status_code_detected(self):
        """Status code diversi → cloaking rilevato."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "bot_googlebot": {
                "status_code": 403,
                "final_url": "https://example.com/page",
                "content_length": 100,
                "body_sha256": "def456",
            },
        }

        cloaking = detect_cloaking(results)
        assert cloaking["cloaking_detected"] is True
        assert "bot_googlebot" in cloaking["divergent_profiles"]

    def test_divergent_body_hash_detected(self):
        """Body hash diversi → cloaking rilevato."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "mobile_safari": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 8000,
                "body_sha256": "different_hash",
            },
        }

        cloaking = detect_cloaking(results)
        assert cloaking["cloaking_detected"] is True

    def test_divergent_final_url_detected(self):
        """URL finali diversi → cloaking rilevato."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "final_url": "https://example.com/real",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "bot_googlebot": {
                "status_code": 200,
                "final_url": "https://example.com/fake",
                "content_length": 100,
                "body_sha256": "def456",
            },
        }

        cloaking = detect_cloaking(results)
        assert cloaking["cloaking_detected"] is True

    def test_single_successful_profile_no_cloaking(self):
        """Un solo profilo ha successo → no cloaking (non confrontabile)."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "final_url": "https://example.com/page",
                "content_length": 5000,
                "body_sha256": "abc123",
            },
            "bot_googlebot": {
                "error": "Connection refused",
                "status_code": None,
                "final_url": None,
                "content_length": None,
                "body_sha256": None,
            },
        }

        cloaking = detect_cloaking(results)
        assert cloaking["cloaking_detected"] is False


class TestRecommendProfile:
    """Raccomandazione profilo per L4."""

    def test_no_cloaking_recommends_desktop_chrome(self):
        """Nessun cloaking → desktop_chrome di default."""
        cloaking = {"cloaking_detected": False}
        profile = recommend_profile({}, cloaking)

        assert profile["user_agent"] == PROFILES["desktop_chrome"]["user_agent"]
        assert "Accept-Language" in profile["headers"]

    def test_cloaking_recommends_richest_profile(self):
        """Cloaking rilevato → profilo con content_length maggiore."""
        results = {
            "desktop_chrome": {
                "status_code": 200,
                "content_length": 5000,
                "final_url": "https://example.com/page",
                "body_sha256": "abc",
            },
            "mobile_safari": {
                "status_code": 200,
                "content_length": 12000,
                "final_url": "https://example.com/page",
                "body_sha256": "abc",
            },
        }
        cloaking = {
            "cloaking_detected": True,
            "divergent_profiles": ["bot_googlebot"],
        }

        profile = recommend_profile(results, cloaking)

        # Deve scegliere mobile_safari (content_length 12000 > 5000)
        assert profile["user_agent"] == PROFILES["mobile_safari"]["user_agent"]


class TestProfiles:
    """Verifica che i profili siano ben formati."""

    def test_at_least_four_profiles(self):
        """Almeno 4 profili predefiniti."""
        assert len(PROFILES) >= 4

    def test_each_profile_has_user_agent(self):
        """Ogni profilo deve avere user_agent."""
        for name, profile in PROFILES.items():
            assert "user_agent" in profile, f"{name} manca di user_agent"
            assert len(profile["user_agent"]) > 20

    def test_profile_names_match_spec(self):
        """I nomi dei profili specificati esistono."""
        required = {"desktop_chrome", "mobile_safari", "bot_googlebot", "no_referer_desktop"}
        assert required.issubset(set(PROFILES.keys()))


class TestClientFactory:
    """Verifica che la factory crei client con gli header corretti."""

    def test_user_agent_set_in_headers(self):
        """Lo User-Agent del profilo viene impostato negli header del client."""
        profile = PROFILES["desktop_chrome"]
        client = _make_client_for_profile(profile)

        assert client.headers["User-Agent"] == profile["user_agent"]
        assert "Accept-Language" in client.headers
