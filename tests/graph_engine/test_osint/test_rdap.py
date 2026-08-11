"""Tests for the RDAP query with IANA bootstrap."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from graph_engine.osint.rdap import (
    _build_rdap_url,
    _extract_rdap_info,
    _extract_tld,
    _parse_rdap_date,
    query_rdap,
)


# ---------------------------------------------------------------------------
# IANA bootstrap mockato
# ---------------------------------------------------------------------------

def _make_iana_bootstrap_response() -> dict:
    """Risposta bootstrap IANA semplificata."""
    return {
        "services": [
            [
                ["com", "net"],
                ["https://rdap.verisign.com/rdap/v1/"],
            ],
            [
                ["it"],
                ["https://rdap.nic.it/rdap/v1/"],
            ],
            [
                ["org"],
                ["https://rdap.pir.org/org/v1/"],
            ],
        ]
    }


def _make_rdap_response() -> dict:
    """Risposta RDAP simulata per un dominio."""
    return {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "events": [
            {
                "eventAction": "registration",
                "eventDate": "2020-03-15T10:00:00Z",
            },
            {
                "eventAction": "expiration",
                "eventDate": "2026-03-15T10:00:00Z",
            },
        ],
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Example Registrar Inc."],
                    ],
                ],
            },
        ],
        "nameservers": [
            {"objectClassName": "nameserver", "ldhName": "ns1.example.com"},
            {"objectClassName": "nameserver", "ldhName": "ns2.example.com"},
        ],
    }


# ---------------------------------------------------------------------------
# Test helper puri (senza HTTP)
# ---------------------------------------------------------------------------


class TestExtractTld:
    def test_simple_tld(self):
        assert _extract_tld("example.com") == "com"

    def test_two_part_tld(self):
        assert _extract_tld("example.co.uk") == "co.uk"

    def test_three_part_tld_gov_it(self):
        assert _extract_tld("inps.gov.it") == "gov.it"


class TestParseRdapDate:
    def test_iso_with_z(self):
        dt = _parse_rdap_date("2020-03-15T10:00:00Z")
        assert dt is not None
        assert dt.year == 2020
        assert dt.month == 3

    def test_iso_with_microseconds_and_z(self):
        dt = _parse_rdap_date("2020-03-15T10:00:00.123456Z")
        assert dt is not None

    def test_iso_without_timezone(self):
        dt = _parse_rdap_date("2020-03-15T10:00:00")
        assert dt is not None
        assert dt.year == 2020

    def test_date_only(self):
        dt = _parse_rdap_date("2020-03-15")
        assert dt is not None

    def test_empty_string(self):
        assert _parse_rdap_date("") is None

    def test_none(self):
        assert _parse_rdap_date(None) is None  # type: ignore[arg-type]


class TestBuildRdapUrl:
    def test_standard_case(self):
        url = _build_rdap_url("https://rdap.verisign.com/rdap/v1/", "example.com")
        assert url == "https://rdap.verisign.com/rdap/v1/domain/example.com"

    def test_no_trailing_slash(self):
        url = _build_rdap_url("https://rdap.nic.it/rdap/v1", "example.it")
        assert url == "https://rdap.nic.it/rdap/v1/domain/example.it"


class TestExtractRdapInfo:
    def test_full_response(self):
        data = _make_rdap_response()
        result = _extract_rdap_info(data)

        assert result["domain_age_days"] is not None
        assert result["domain_age_days"] > 0
        assert result["registrar"] == "Example Registrar Inc."
        assert set(result["nameservers"]) == {"ns1.example.com", "ns2.example.com"}

    def test_no_events(self):
        result = _extract_rdap_info({"objectClassName": "domain"})
        assert result["domain_age_days"] is None
        assert result["registrar"] is None
        assert result["nameservers"] == []


# ---------------------------------------------------------------------------
# Test query_rdap con mock httpx
# ---------------------------------------------------------------------------


class TestQueryRdapMocked:
    @patch("graph_engine.osint.rdap.cache_get", return_value=None)
    async def test_successful_query(self, mock_cache, monkeypatch):
        """query_rdap completa: bootstrap + query RDAP → dati estratti."""
        # Mock IANA bootstrap
        iana_resp = MagicMock()
        iana_resp.json.return_value = _make_iana_bootstrap_response()
        iana_resp.raise_for_status = MagicMock()

        # Mock RDAP response
        rdap_resp = MagicMock()
        rdap_resp.json.return_value = _make_rdap_response()
        rdap_resp.raise_for_status = MagicMock()
        rdap_resp.status_code = 200

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=[iana_resp, rdap_resp])

        result = await query_rdap("example.com", mock_client)

        assert "error" not in result
        assert result["domain_age_days"] is not None
        assert result["domain_age_days"] > 0
        assert result["registrar"] == "Example Registrar Inc."

    @patch("graph_engine.osint.rdap.cache_get", return_value=None)
    async def test_domain_not_found(self, mock_cache, monkeypatch):
        """Dominio non trovato in RDAP → 404, error informativo."""
        iana_resp = MagicMock()
        iana_resp.json.return_value = _make_iana_bootstrap_response()
        iana_resp.raise_for_status = MagicMock()

        rdap_resp = MagicMock()
        rdap_resp.status_code = 404

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=[iana_resp, rdap_resp])

        result = await query_rdap("nonexistent-12345.com", mock_client)

        assert "error" in result
        assert "not found" in result["error"].lower()
        assert result["nameservers"] == []

    @patch("graph_engine.osint.rdap.cache_get", return_value=None)
    async def test_tld_not_in_bootstrap(self, mock_cache, monkeypatch):
        """TLD non presente nel bootstrap IANA → error."""
        iana_resp = MagicMock()
        iana_resp.json.return_value = {
            "services": [
                [["com"], ["https://rdap.example.com/"]],
            ]
        }
        iana_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=iana_resp)

        result = await query_rdap("example.xyznonexistenttld", mock_client)

        assert "error" in result
        assert "No RDAP server found" in result["error"]

    @patch("graph_engine.osint.rdap.cache_get", return_value=None)
    async def test_timeout(self, mock_cache, monkeypatch):
        """Timeout durante il bootstrap → error, mai eccezione."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=httpx.TimeoutException("timed out")
        )

        result = await query_rdap("example.com", mock_client)

        assert "error" in result

    @patch("graph_engine.osint.rdap.cache_get", return_value=None)
    async def test_uses_registrable_domain_for_cache(self, mock_cache, monkeypatch):
        """La query usa il dominio registrabile (eTLD+1), non l'hostname completo."""
        iana_resp = MagicMock()
        iana_resp.json.return_value = _make_iana_bootstrap_response()
        iana_resp.raise_for_status = MagicMock()

        rdap_resp = MagicMock()
        rdap_resp.json.return_value = _make_rdap_response()
        rdap_resp.raise_for_status = MagicMock()
        rdap_resp.status_code = 200

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=[iana_resp, rdap_resp])

        # Passa un sottodominio — dovrebbe interrogare il dominio registrabile
        result = await query_rdap("sub.domain.example.com", mock_client)

        assert "error" not in result
        # Verifica che la chiamata RDAP sia per example.com, non per il sottodominio
        rdap_calls = [
            c for c in mock_client.get.call_args_list
            if "/domain/" in str(c)
        ]
        assert len(rdap_calls) == 1
        assert "example.com" in str(rdap_calls[0])
        assert "sub.domain" not in str(rdap_calls[0])
