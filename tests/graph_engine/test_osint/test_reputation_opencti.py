"""Tests per OpenCTI — osservabili STIX, filtro eq e semantica IOC-attivo.

Il file ``test_reputation_misp_opencti_disabled.py`` copre il caso
"disabilitato senza configurazione"; questo file copre il provider
CONFIGURATO, mockando il confine httpx (mai rete reale).

Forma della query verificata contro la documentazione ufficiale
(docs.opencti.io) e il sorgente ``OpenCTI-Platform/opencti``:
``stixCyberObservables`` con filtro ``{ key: ["value"], values: [x],
operator: eq }`` per valore candidato (confronto esatto, senza sintassi
Lucene), combinati con ``FilterGroup`` ``mode: or``; ``indicators``
annidato sull'osservabile per la semantica IOC-attivo.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx

from graph_engine.config import settings
from graph_engine.osint.reputation.opencti import OpenCtiProvider

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

_EXPECTED_TYPES = ["Url", "Hostname", "Domain-Name", "IPv4-Addr", "IPv6-Addr"]


def _enable_opencti(monkeypatch):
    """Configura il singleton settings come se OpenCTI fosse attivo."""
    monkeypatch.setattr(settings, "opencti_url", "https://opencti.example")
    monkeypatch.setattr(settings, "opencti_api_key", "test-key")


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

_IND_ACTIVE = {
    "id": "indicator-uuid-1",
    "name": "INPS phishing URL",
    "pattern_type": "stix",
    "revoked": False,
    "valid_until": "2099-01-01T00:00:00Z",
    "x_opencti_score": 85,
    "x_opencti_detection": True,
    "createdBy": {"name": "CERT-AGID"},
    "objectLabel": [{"value": "phishing"}],
}

_OBS_URL_ACTIVE = {
    "id": "observable-uuid-1",
    "entity_type": "Url",
    "observable_value": _TEST_URL,
    "x_opencti_score": 90,
    "objectMarking": [{"definition": "TLP:AMBER", "definition_type": "TLP"}],
    "objectLabel": [{"value": "phishing"}],
    "createdBy": {"name": "CERT-AGID"},
    "indicators": {"edges": [{"node": _IND_ACTIVE}]},
}


def _response(*observables) -> dict:
    return {
        "data": {
            "stixCyberObservables": {
                "pageInfo": {"globalCount": len(observables)},
                "edges": [{"node": o} for o in observables],
            }
        }
    }


# ---------------------------------------------------------------------------
# Body della query GraphQL
# ---------------------------------------------------------------------------


class TestGraphQlBody:
    async def test_body_contains_all_candidate_values(self, monkeypatch):
        """Le variabili DEVONO contenere i 5 tipi osservabili e un filtro
        ``eq`` per ogni valore candidato, OR a livello di gruppo."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response())
        provider = OpenCtiProvider()

        await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        call = mock_client.post.call_args
        body = call.kwargs["json"]
        assert "stixCyberObservables" in body["query"]
        variables = body["variables"]
        assert variables["types"] == _EXPECTED_TYPES
        filters = variables["filters"]
        assert filters["mode"] == "or"
        assert filters["filterGroups"] == []
        assert [
            f["values"][0] for f in filters["filters"]
        ] == _EXPECTED_VALUES
        assert all(
            f["operator"] == "eq" and f["key"] == ["value"]
            for f in filters["filters"]
        ), (
            "ogni candidato va cercato con eq esatto (nessuna sintassi "
            "Lucene/wildcard)"
        )

    async def test_auth_header_bearer_token(self, monkeypatch):
        """L'header DEVE essere ``Authorization: Bearer <key>`` su /graphql."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response())
        provider = OpenCtiProvider()

        await provider.check(_TEST_URL, mock_client)

        call = mock_client.post.call_args
        assert call.kwargs["headers"]["Authorization"] == "Bearer test-key"
        assert "https://opencti.example/graphql" in str(call.args[0]) or \
               call.args[0] == "https://opencti.example/graphql"

    async def test_known_ips_none_is_fine(self, monkeypatch):
        """known_ips=None (default) → la query copre url/hostname/dominio
        e non si rompe."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response())
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        body = mock_client.post.call_args.kwargs["json"]
        flat = [f["values"][0] for f in body["variables"]["filters"]["filters"]]
        assert flat == _EXPECTED_VALUES[:3]  # nessun IP
        assert result["listed"] is False
        assert result["details"]["match_count"] == 0

    async def test_duplicate_values_deduplicated(self, monkeypatch):
        """IP già presenti tra i candidati (es. hostname che È un IP)
        non devono comparire due volte nei filtri."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response())
        provider = OpenCtiProvider()

        await provider.check(
            "https://1.2.3.4/login", mock_client, known_ips=["1.2.3.4"]
        )

        body = mock_client.post.call_args.kwargs["json"]
        flat = [f["values"][0] for f in body["variables"]["filters"]["filters"]]
        assert flat.count("1.2.3.4") == 1


# ---------------------------------------------------------------------------
# Semantica del risultato (IOC-attivo)
# ---------------------------------------------------------------------------


class TestActiveIocSemantics:
    async def test_active_indicator_means_listed(self, monkeypatch):
        """Osservabile con almeno un Indicator attivo → listed=True con
        dettagli estratti compatti (mai payload grezzo)."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response(_OBS_URL_ACTIVE))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["provider"] == "opencti"
        assert result["listed"] is True
        details = result["details"]
        assert details["match_count"] == 1
        assert details["matched_types"] == ["Url"]
        assert details["active_indicator_count"] == 1
        assert details["total_indicator_count"] == 1
        assert details["labels"] == ["phishing"]
        assert details["markings"] == ["TLP:AMBER"]
        assert details["created_by"] == ["CERT-AGID"]
        assert details["score_min"] == 85
        assert details["score_max"] == 85
        assert details["score_avg"] == 85.0
        assert details["active_ioc_match"] is True
        assert details["context_only"] is False
        # Nessun payload grezzo: le chiavi sono solo quelle riepilogate
        assert set(details.keys()) == {
            "match_count", "matched_types", "active_indicator_count",
            "total_indicator_count", "labels", "markings", "created_by",
            "score_min", "score_max", "score_avg",
            "active_ioc_match", "context_only",
        }

    async def test_revoked_indicator_is_context_only(self, monkeypatch):
        """Osservabile con SOLO indicator revoked → listed=False ma
        context_only=True: l'IOC esiste ma non è più attivo."""
        _enable_opencti(monkeypatch)
        obs = dict(_OBS_URL_ACTIVE)
        obs["indicators"] = {
            "edges": [{"node": dict(_IND_ACTIVE, revoked=True)}]
        }
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        details = result["details"]
        assert details["match_count"] == 1
        assert details["active_indicator_count"] == 0
        assert details["total_indicator_count"] == 1
        assert details["active_ioc_match"] is False
        assert details["context_only"] is True

    async def test_expired_indicator_is_context_only(self, monkeypatch):
        """valid_until nel passato → indicatore scaduto, NON attivo."""
        _enable_opencti(monkeypatch)
        obs = dict(_OBS_URL_ACTIVE)
        obs["indicators"] = {
            "edges": [
                {"node": dict(_IND_ACTIVE, valid_until="2000-01-01T00:00:00Z")}
            ]
        }
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert result["details"]["context_only"] is True

    async def test_unparseable_valid_until_is_not_active(self, monkeypatch):
        """valid_until illeggibile → conservativo: l'indicatore NON è
        considerato attivo (la decisione deterministica non si basa su
        dati incomprensibili)."""
        _enable_opencti(monkeypatch)
        obs = dict(_OBS_URL_ACTIVE)
        obs["indicators"] = {
            "edges": [
                {"node": dict(_IND_ACTIVE, valid_until="domani, forse")}
            ]
        }
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert result["details"]["context_only"] is True

    async def test_naive_valid_until_treated_as_utc(self, monkeypatch):
        """DateTime senza offset (naive) → trattato come UTC, resta attivo
        (ramo Python 3.9: fromisoformat non normalizza gli aware)."""
        _enable_opencti(monkeypatch)
        obs = dict(_OBS_URL_ACTIVE)
        obs["indicators"] = {
            "edges": [
                {"node": dict(_IND_ACTIVE, valid_until="2099-01-01T00:00:00")}
            ]
        }
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is True

    async def test_observable_without_indicators_is_context_only(self, monkeypatch):
        """Osservabile senza alcun Indicator correlato → non è un IOC:
        contesto informativo, non un hit."""
        _enable_opencti(monkeypatch)
        obs = {
            "id": "observable-uuid-2",
            "entity_type": "Domain-Name",
            "observable_value": "inps.gov.it",
            "x_opencti_score": 60,
            "objectMarking": [],
            "objectLabel": [],
            "createdBy": None,
        }
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert result["details"]["match_count"] == 1
        assert result["details"]["active_indicator_count"] == 0
        assert result["details"]["context_only"] is True

    async def test_mixed_observables_active_wins(self, monkeypatch):
        """Un osservabile attivo basta per listed=True, i conteggi
        restano separati e gli score coprono SOLO gli attivi."""
        _enable_opencti(monkeypatch)
        revoked_obs = dict(_OBS_URL_ACTIVE)
        revoked_obs["entity_type"] = "Domain-Name"
        revoked_obs["indicators"] = {
            "edges": [{"node": dict(_IND_ACTIVE, revoked=True)}]
        }
        active2 = dict(_OBS_URL_ACTIVE)
        active2["indicators"] = {
            "edges": [
                {"node": dict(_IND_ACTIVE, x_opencti_score=95)}
            ]
        }
        mock_client = _mock_client(
            monkeypatch, _response(_OBS_URL_ACTIVE, revoked_obs, active2)
        )
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is True
        details = result["details"]
        assert details["match_count"] == 3
        assert details["matched_types"] == ["Domain-Name", "Url"]
        assert details["active_indicator_count"] == 2
        assert details["total_indicator_count"] == 3
        assert details["score_min"] == 85
        assert details["score_max"] == 95
        assert details["score_avg"] == 90.0

    async def test_no_match_is_clean_false(self, monkeypatch):
        """Nessun osservabile → listed=False pulito, senza context_only."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(monkeypatch, _response())
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is False
        assert result["details"]["match_count"] == 0
        assert result["details"]["context_only"] is False
        assert result["details"]["active_ioc_match"] is False


# ---------------------------------------------------------------------------
# Robustezza
# ---------------------------------------------------------------------------


class TestRobustness:
    async def test_error_is_fail_clean(self, monkeypatch):
        """Errore di rete/timeout → listed=False con details.error,
        MAI un'eccezione che risale."""
        _enable_opencti(monkeypatch)
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.TimeoutException("boom")
        )
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client, known_ips=_TEST_IPS)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_malformed_response_is_fail_clean(self, monkeypatch):
        """Risposta malformata (edges non lista) → fail-clean."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(
            monkeypatch,
            {"data": {"stixCyberObservables": {"edges": "nonsense"}}},
        )
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert "error" in result["details"]

    async def test_malformed_nested_indicator_edges_do_not_crash(self, monkeypatch):
        """``indicators.edges`` non lista sull'osservabile → trattato come
        assenza di indicatori (context_only), nessun crash."""
        _enable_opencti(monkeypatch)
        obs = dict(_OBS_URL_ACTIVE)
        obs["indicators"] = {"edges": "nonsense"}
        mock_client = _mock_client(monkeypatch, _response(obs))
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert result["details"]["match_count"] == 1
        assert result["details"]["context_only"] is True

    async def test_non_dict_nodes_skipped(self, monkeypatch):
        """Node non-dict tra gli edges → saltato senza crash."""
        _enable_opencti(monkeypatch)
        mock_client = _mock_client(
            monkeypatch,
            {"data": {"stixCyberObservables": {"edges": [{"node": None}]}}},
        )
        provider = OpenCtiProvider()

        result = await provider.check(_TEST_URL, mock_client)

        assert result["listed"] is False
        assert result["details"]["match_count"] == 0
