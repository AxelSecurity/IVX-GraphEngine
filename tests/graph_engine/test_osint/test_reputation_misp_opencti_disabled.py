"""Tests for MISP/OpenCTI — disabilitati di default.

Verifica che SENZA configurazione:
1. Nessuna chiamata HTTP venga mai tentata
2. Il risultato sia listed=False con skipped

La configurazione si forza azzerando i campi del singleton
``graph_engine.config.settings`` (la fonte centralizzata da cui i
provider leggono, al posto di ``os.environ``).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import requests

from graph_engine.config import settings


def _disable_misp(monkeypatch):
    """Forza la configurazione MISP a vuoto sul singleton."""
    monkeypatch.setattr(settings, "misp_url", None)
    monkeypatch.setattr(settings, "misp_api_key", None)


def _disable_opencti(monkeypatch):
    """Forza la configurazione OpenCTI a vuoto sul singleton."""
    monkeypatch.setattr(settings, "opencti_url", None)
    monkeypatch.setattr(settings, "opencti_api_key", None)


class TestMispDisabled:
    async def test_not_configured_skips(self, monkeypatch):
        """Senza MISP_URL/MISP_API_KEY → skipped, nessuna HTTP."""
        from graph_engine.osint.reputation.misp import MispProvider

        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        _disable_misp(monkeypatch)
        provider = MispProvider()
        result = await provider.check("http://evil.example", mock_client)

        assert result["provider"] == "misp"
        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        # NESSUNA chiamata HTTP
        mock_client.post.assert_not_called()

    async def test_not_configured_no_http_even_on_error(self, monkeypatch):
        """Anche con client non funzionante, se disabilitato nessuna chiamata."""
        from graph_engine.osint.reputation.misp import MispProvider

        mock_client = MagicMock()

        _disable_misp(monkeypatch)
        provider = MispProvider()
        result = await provider.check(
            "http://evil.example",
            mock_client,
        )

        assert result["listed"] is False
        mock_client.post.assert_not_called()


class TestOpenCtiDisabled:
    async def test_not_configured_skips(self, monkeypatch):
        """Senza OPENCTI_URL/OPENCTI_API_KEY → skipped, nessuna HTTP."""
        from graph_engine.osint.reputation.opencti import OpenCtiProvider

        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        _disable_opencti(monkeypatch)
        provider = OpenCtiProvider()
        result = await provider.check("http://evil.example", mock_client)

        assert result["provider"] == "opencti"
        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        mock_client.post.assert_not_called()

    async def test_not_configured_no_http_even_on_error(self, monkeypatch):
        """Anche con client non funzionante, se disabilitato nessuna chiamata."""
        from graph_engine.osint.reputation.opencti import OpenCtiProvider

        mock_client = MagicMock()

        _disable_opencti(monkeypatch)
        provider = OpenCtiProvider()
        result = await provider.check(
            "http://evil.example",
            mock_client,
        )

        assert result["listed"] is False
        mock_client.post.assert_not_called()


class TestNetworkBlockedExplicit:
    """Test di blocco rete esplicito per MISP/OpenCTI — stesso pattern di tldextract.

    Se non configurati, MISP e OpenCTI NON devono MAI tentare richieste HTTP.
    Lo verifichiamo con un monkeypatch su requests.Session.send (stesso pattern
    del test_network_isolation per tldextract).
    """

    async def test_misp_no_network_when_disabled(self, monkeypatch):
        """MISP disabilitato → blocco rete esplicito, zero chiamate."""
        from graph_engine.osint.reputation.misp import MispProvider

        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        _disable_misp(monkeypatch)
        provider = MispProvider()

        # Blocco requests.Session.send come test di sicurezza aggiuntivo
        def _blocked(*args, **kwargs):
            raise RuntimeError(
                "RETE BLOCCATA: MISP ha tentato una richiesta HTTP!"
            )

        with patch.object(requests.Session, "send", _blocked):
            result = await provider.check(
                "http://evil.example",
                mock_client,
            )

        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        # Verifica ATTIVA: il client httpx non deve mai essere invocato
        mock_client.post.assert_not_called()

    async def test_opencti_no_network_when_disabled(self, monkeypatch):
        """OpenCTI disabilitato → blocco rete esplicito, zero chiamate."""
        from graph_engine.osint.reputation.opencti import OpenCtiProvider

        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        _disable_opencti(monkeypatch)
        provider = OpenCtiProvider()

        def _blocked(*args, **kwargs):
            raise RuntimeError(
                "RETE BLOCCATA: OpenCTI ha tentato una richiesta HTTP!"
            )

        with patch.object(requests.Session, "send", _blocked):
            result = await provider.check(
                "http://evil.example",
                mock_client,
            )

        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        # Verifica ATTIVA: il client httpx non deve mai essere invocato
        mock_client.post.assert_not_called()


class TestMispOpenCtiTimeoutPropagation:
    """Il ``timeout_s`` dell'analisi (es. ``FAST_L2_TIMEOUT_S=5.0`` nel
    path Trellix) DEVE raggiungere la chiamata HTTP dei provider
    configurati: senza, il floor resterebbe ``MISP_TIMEOUT``/
    ``OPENCTI_TIMEOUT`` = 15s e il fast profile non avrebbe effetto."""

    async def test_misp_timeout_s_passed_to_http_call(self, monkeypatch):
        from graph_engine.osint.reputation.misp import MISP_TIMEOUT, MispProvider

        monkeypatch.setattr(settings, "misp_url", "https://misp.example")
        monkeypatch.setattr(settings, "misp_api_key", "test-key")

        mock_response = MagicMock()
        mock_response.json.return_value = {"response": {"Attribute": []}}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = MispProvider()
        await provider.check(
            "http://timeout-probe.example", mock_client, timeout_s=5.0
        )

        assert mock_client.post.call_args.kwargs["timeout"] == 5.0

    async def test_misp_default_timeout_without_timeout_s(self, monkeypatch):
        from graph_engine.osint.reputation.misp import MISP_TIMEOUT, MispProvider

        monkeypatch.setattr(settings, "misp_url", "https://misp.example")
        monkeypatch.setattr(settings, "misp_api_key", "test-key")

        mock_response = MagicMock()
        mock_response.json.return_value = {"response": {"Attribute": []}}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = MispProvider()
        await provider.check("http://timeout-probe.example", mock_client)

        assert mock_client.post.call_args.kwargs["timeout"] == MISP_TIMEOUT

    async def test_opencti_timeout_s_passed_to_http_call(self, monkeypatch):
        from graph_engine.osint.reputation.opencti import (
            OPENCTI_TIMEOUT,
            OpenCtiProvider,
        )

        monkeypatch.setattr(settings, "opencti_url", "https://opencti.example")
        monkeypatch.setattr(settings, "opencti_api_key", "test-key")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {"stixCyberObservables": {"edges": []}}
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = OpenCtiProvider()
        await provider.check(
            "http://timeout-probe.example", mock_client, timeout_s=5.0
        )

        assert mock_client.post.call_args.kwargs["timeout"] == 5.0

    async def test_opencti_default_timeout_without_timeout_s(self, monkeypatch):
        from graph_engine.osint.reputation.opencti import (
            OPENCTI_TIMEOUT,
            OpenCtiProvider,
        )

        monkeypatch.setattr(settings, "opencti_url", "https://opencti.example")
        monkeypatch.setattr(settings, "opencti_api_key", "test-key")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {"stixCyberObservables": {"edges": []}}
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        provider = OpenCtiProvider()
        await provider.check("http://timeout-probe.example", mock_client)

        assert mock_client.post.call_args.kwargs["timeout"] == OPENCTI_TIMEOUT
