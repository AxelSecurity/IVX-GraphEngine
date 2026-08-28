"""Tests per MISP — query multi-tipo, includeContext e semantica to_ids.

Il file ``test_reputation_misp_opencti_disabled.py`` copre il caso
"disabilitato senza configurazione"; questo file copre il provider
CONFIGURATO, mockando il confine httpx (mai rete reale).

Forma della query verificata contro la documentazione ufficiale MISP
(OpenAPI ``/attributes/restSearch`` e sorgente 2.4): ``value`` e
``type`` accettano liste nel body JSON; ``includeContext: 1`` annida
l'oggetto ``Event`` completo in ogni attributo della risposta.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import requests

from graph_engine.config import settings
from graph_engine.osint.reputation.misp import MispProvider

# URL di test: hostname con subdomain su eTLD pubblico italiano
# (login.inps.gov.it → reg_domain inps.gov.it).
_TEST_URL = "https://login.inps.gov.it/pagamento"
_TEST_IPS = ["1.2.3.4", "2001:db8::1"]

_EXPECTED_VALUES = [
    _TEST_URL,                      # URL completo
    "login.inps.gov.it",            # hostname
    "inps.gov.it",                  # dominio registrabile (eTLD+1)
    "1.2.3.4",                      # IP da known_ips
    "2001:db8::1",
]


def _enable_misp(monkeypatch):
    """Configura il singleton settings come se MISP fosse attivo."""
    monkeypatch.setattr(settings, "misp_url", "https://misp.example")
    monkeypatch.setattr(settings, "misp_api_key", "test-key")


def _mock_client(monkeypatch, json_response):
    """Client httpx finto con risposta JSON controllata."""
    mock_response = MagicMock()
    mock_response.json.return_value = json_response
    mock_response.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    return mock_client


# ---------------------------------------------------------------------------
# Payload di risposta riusabili
# ---------------------------------------------------------------------------

_ATTR_DOMAIN_TO_IDS = {
    "id": "1",
    "event_id": "42",
    "type": "domain",
    "value": "evil.example.com",
    "to_ids": True,
    "Tag": [{"name": "tlp:white"}],
    "Event": {
        "id": "42",
        "info": "Phishing kit campaign",
        "threat_level_id": "1",
        "Tag": [{"name": "phishing"}, {"name": "tlp:white"}],
    },
}

_ATTR_IP_NO_IDS = {
    "id": "2",
    "event_id": "43",
    "type": "ip-dst",
    "value": "1.2.3.4",
    "to_ids": False,
    "Tag": [],
    "Event": {
        "id": "43",
        "info": "Shared infrastructure",
        "threat_level_id": "2",
        "Tag": [{"name": "phishing"}],
    },
}


# ---------------------------------------------------------------------------
# Blocco rete quando non configurato
# ---------------------------------------------------------------------------


class TestNetworkBlockedWhenNotConfigured:
    async def test_no_network_when_disabled(self, monkeypatch):
        """Non configurato → blocco rete esplicito, zero chiamate HTTP."""
        mock_client = MagicMock()
        mock_client.post = AsyncMock()

        monkeypatch.setattr(settings, "misp_url", None)
        monkeypatch.setattr(settings, "misp_api_key", None)
        provider = MispProvider()

        def _blocked(*args, **kwargs):
            raise RuntimeError(
                "RETE BLOCCATA: MISP ha tentato una richiesta HTTP!"
            )

        with patch.object(requests.Session, "send", _blocked):
            result = await provider.check(
                _TEST_URL, mock_client, known_ips=_TEST_IPS
            )

        assert result["listed"] is False
        assert result["details"]["skipped"] == "not configured"
        mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Body della query restSearch
# ---------------------------------------------------------------------------


class TestRestSearchBody:
    async def test_body_contains_all_candidate_values(self, monkeypatch):
        """Il body DEVE contenere url, hostname, dominio registrabile
        e gli IP passati — tutti nella lista ``value``, con ``type``
        multi-tipo e ``includeContext`` attivo."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(
            monkeypatch, {"response": {"Attribute": []}}
        )
        provider = MispProvider()

        await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        body = mock_client.post.call_args.kwargs["json"]
        assert body["value"] == _EXPECTED_VALUES
        assert body["type"] == ["domain", "hostname", "url", "ip-dst"]
        assert body["includeContext"] == 1
        assert body["returnFormat"] == "json"

    async def test_known_ips_none_is_fine(self, monkeypatch):
        """known_ips=None (default) → la query copre url/hostname/dominio
        e non si rompe."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(
            monkeypatch, {"response": {"Attribute": []}}
        )
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client)

        body = mock_client.post.call_args.kwargs["json"]
        assert body["value"] == _EXPECTED_VALUES[:3]  # nessun IP
        assert result["listed"] is False
        assert result["details"]["match_count"] == 0

    async def test_duplicate_values_deduplicated(self, monkeypatch):
        """IP già presenti tra i candidati (es. hostname che È un IP)
        non devono comparire due volte in ``value``."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(
            monkeypatch, {"response": {"Attribute": []}}
        )
        provider = MispProvider()

        await provider.check(
            "https://1.2.3.4/login", mock_client, known_ips=["1.2.3.4"]
        )

        body = mock_client.post.call_args.kwargs["json"]
        assert body["value"].count("1.2.3.4") == 1


# ---------------------------------------------------------------------------
# Semantica del risultato (to_ids-aware)
# ---------------------------------------------------------------------------


class TestToIdsSemantics:
    async def test_to_ids_true_means_listed(self, monkeypatch):
        """Almeno un match con to_ids=true → listed=True con dettagli
        estratti compatti (mai payload grezzo)."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(monkeypatch, {
            "response": {
                "Attribute": [_ATTR_DOMAIN_TO_IDS, _ATTR_IP_NO_IDS]
            }
        })
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["provider"] == "misp"
        assert result["listed"] is True
        details = result["details"]
        assert details["match_count"] == 2
        assert details["matched_types"] == ["domain", "ip-dst"]
        # Tag deduplicati da Attribute E da Event (tlp:white appare
        # su entrambi i livelli ma va contato una volta sola)
        assert details["tags"] == ["phishing", "tlp:white"]
        assert details["event_count"] == 2
        assert details["to_ids_match"] is True
        assert details["context_only"] is False
        # Nessun payload grezzo: le chiavi sono solo quelle riepilogate
        assert set(details.keys()) == {
            "match_count", "matched_types", "tags",
            "event_count", "to_ids_match", "context_only",
        }

    async def test_only_to_ids_false_means_context_only(self, monkeypatch):
        """Solo match to_ids=false → listed=False ma context_only=True:
        contesto informativo, NON equiparato a un hit."""
        _enable_misp(monkeypatch)
        attr_no_ids_1 = dict(_ATTR_DOMAIN_TO_IDS, to_ids=False)
        attr_no_ids_2 = dict(_ATTR_IP_NO_IDS, to_ids=False)
        mock_client = _mock_client(monkeypatch, {
            "response": {"Attribute": [attr_no_ids_1, attr_no_ids_2]}
        })
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is False
        details = result["details"]
        assert details["match_count"] == 2
        assert details["to_ids_match"] is False
        assert details["context_only"] is True

    async def test_no_match_is_clean_false(self, monkeypatch):
        """Nessun attributo → listed=False pulito, senza context_only."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(
            monkeypatch, {"response": {"Attribute": []}}
        )
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is False
        assert result["details"]["match_count"] == 0
        assert result["details"]["context_only"] is False
        assert result["details"]["to_ids_match"] is False

    async def test_single_attribute_dict_normalised(self, monkeypatch):
        """Alcuni server serializzano UN oggetto invece di una lista
        con un solo match — va normalizzato, non scartato."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(monkeypatch, {
            "response": {"Attribute": _ATTR_DOMAIN_TO_IDS}
        })
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is True
        assert result["details"]["match_count"] == 1
        assert result["details"]["event_count"] == 1

    async def test_error_is_fail_clean(self, monkeypatch):
        """Errore di rete/timeout → listed=False con details.error,
        MAI un'eccezione che risale."""
        _enable_misp(monkeypatch)
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.TimeoutException("boom")
        )
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_malformed_response_is_fail_clean(self, monkeypatch):
        """Risposta malformata (Attribute non lista) → fail-clean."""
        _enable_misp(monkeypatch)
        mock_client = _mock_client(
            monkeypatch, {"response": {"Attribute": "nonsense"}}
        )
        provider = MispProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]
