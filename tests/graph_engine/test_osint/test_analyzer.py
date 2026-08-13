"""Tests d'integrazione per l'analyzer L2."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from graph_engine.config import settings
from graph_engine.osint.analyzer import analyze


class TestAnalyzerIntegration:
    async def test_all_sources_in_parallel(self, monkeypatch):
        """Verifica che le fonti vengano chiamate (anche se mockate)."""
        # URLhaus è condizionale alla Auth-Key: la configuriamo perché
        # il registry lo includa tra i provider abilitati.
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        # Per questo test, mockiamo direttamente le tre funzioni di query
        # per evitare di dover mockare httpx a più livelli
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
        ) as mock_crtsh, patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
        ) as mock_rdap, patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
        ) as mock_dns, patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
        ) as mock_urlhaus:

            mock_crtsh.return_value = {
                "sibling_domains": ["sibling1.example.com"],
                "truncated": False,
                "total_siblings": 1,
                "newest_cert_days": 30,
                "oldest_cert_days": 365,
                "total_certs": 5,
            }
            mock_rdap.return_value = {
                "domain_age_days": 15,
                "registrar": "TestReg",
                "nameservers": ["ns1.test.com"],
            }
            mock_dns.return_value = {
                "a_records": ["93.184.216.34"],
                "aaaa_records": [],
                "error": None,
            }
            mock_urlhaus.return_value = {
                "provider": "urlhaus",
                "listed": True,
                "details": {"threat": "phishing"},
            }

            result = await analyze("https://evil.example.com/login")

            # Tutte le fonti devono essere state chiamate
            mock_crtsh.assert_called_once()
            mock_rdap.assert_called_once()
            mock_dns.assert_called_once()
            mock_urlhaus.assert_called_once()

    async def test_one_source_failure_doesnt_block_others(self, monkeypatch):
        """Se una fonte fallisce, le altre producono comunque risultati."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
        ) as mock_crtsh, patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
        ) as mock_rdap, patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
        ) as mock_dns, patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
        ) as mock_urlhaus:

            # crt.sh fallisce
            mock_crtsh.side_effect = RuntimeError("crash!")
            # RDAP funziona
            mock_rdap.return_value = {
                "domain_age_days": 5,
                "registrar": "TestReg",
                "nameservers": [],
            }
            # DNS funziona
            mock_dns.return_value = {
                "a_records": ["1.2.3.4"],
                "aaaa_records": [],
                "error": None,
            }
            # URLhaus funziona
            mock_urlhaus.return_value = {
                "provider": "urlhaus",
                "listed": False,
                "details": {"query_status": "no_results"},
            }

            result = await analyze("https://evil.example.com/login")

            # Non deve crashare
            assert "evidence" in result
            assert "passive_risk_score" in result

            # Deve contenere evidenza RDAP (funziona)
            age_ev = [
                e for e in result["evidence"]
                if e["key"] == "domain_age_days"
            ]
            assert len(age_ev) == 1  # 5 giorni → young

            # Deve contenere evidenza DNS (funziona)
            dns_ev = [
                e for e in result["evidence"]
                if e["key"] == "dns_a_records"
            ]
            assert len(dns_ev) == 1

            # crt.sh deve aver fallito → evidenza provider_unavailable
            unavail = [
                e for e in result["evidence"]
                if e["key"] == "provider_unavailable" and "crtsh" in str(e["value"])
            ]
            assert len(unavail) == 1

    async def test_empty_hostname_returns_zero_risk(self):
        """URL senza hostname → rischio 0, nessuna evidenza."""
        result = await analyze("not-a-valid-url")
        assert result["evidence"] == []
        assert result["passive_risk_score"] == 0.0

    async def test_young_domain_increases_risk(self, monkeypatch):
        """Dominio < 30 giorni → peso alto (0.35)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value={"sibling_domains": [], "truncated": False,
                          "total_siblings": 0, "newest_cert_days": None,
                          "oldest_cert_days": None, "total_certs": 0},
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value={"domain_age_days": 7, "registrar": "BadReg",
                          "nameservers": []},
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": ["1.2.3.4"], "aaaa_records": [],
                          "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value={"provider": "urlhaus", "listed": False,
                          "details": {"query_status": "no_results"}},
        ):
            result = await analyze("https://evil.example.com/login")

            assert result["passive_risk_score"] == 0.35  # solo domain_age young

    async def test_reputation_hit_high_weight(self, monkeypatch):
        """URLhaus hit → peso molto alto (0.50)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value={"sibling_domains": [], "truncated": False,
                          "total_siblings": 0, "newest_cert_days": None,
                          "oldest_cert_days": None, "total_certs": 0},
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value={"domain_age_days": 365, "registrar": "GoodReg",
                          "nameservers": []},
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": ["93.184.216.34"], "aaaa_records": [],
                          "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value={"provider": "urlhaus", "listed": True,
                          "details": {"threat": "phishing"}},
        ):
            result = await analyze("https://evil.example.com/login")

            # Dominio vecchio (nessun peso) + URLhaus hit (0.50)
            assert result["passive_risk_score"] == 0.50

            hit_ev = [e for e in result["evidence"] if e["key"] == "reputation_hit"]
            assert len(hit_ev) == 1

    async def test_risk_score_clamped_to_one(self, monkeypatch):
        """Il rischio non supera mai 1.0."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value={
                "sibling_domains": ["s1.com", "s2.com"],
                "truncated": False,
                "total_siblings": 2,
                "newest_cert_days": 5,
                "oldest_cert_days": 30,
                "total_certs": 10,
            },
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value={"domain_age_days": 2, "registrar": "Bad",
                          "nameservers": []},
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": ["1.2.3.4"], "aaaa_records": [],
                          "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value={"provider": "urlhaus", "listed": True,
                          "details": {"threat": "phishing"}},
        ):
            result = await analyze("https://evil.example.com/login")
            # 0.35 + 0.30 + 0.50 = 1.15 → clampato a 1.0
            assert result["passive_risk_score"] <= 1.0

    async def test_evidence_layer_is_l2(self, monkeypatch):
        """Tutte le evidenze devono avere layer='L2'."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value={
                "sibling_domains": ["sib.example.com"],
                "truncated": False, "total_siblings": 1,
                "newest_cert_days": 30, "oldest_cert_days": 60, "total_certs": 3,
            },
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value={"domain_age_days": 10, "registrar": "R",
                          "nameservers": []},
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": ["93.184.216.34"],
                          "aaaa_records": ["::1"], "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value={"provider": "urlhaus", "listed": False,
                          "details": {"query_status": "no_results"}},
        ):
            result = await analyze("https://evil.example.com/login")

            for ev in result["evidence"]:
                assert ev["layer"] == "L2"
                assert ev["scope"] == "target"

    async def test_old_domain_no_penalty(self, monkeypatch):
        """Dominio > 90 giorni → NESSUNA evidenza domain_age (nessuna penalità)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value={"sibling_domains": [], "truncated": False,
                          "total_siblings": 0, "newest_cert_days": None,
                          "oldest_cert_days": None, "total_certs": 0},
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value={"domain_age_days": 365, "registrar": "OldReg",
                          "nameservers": []},
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": ["93.184.216.34"], "aaaa_records": [],
                          "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value={"provider": "urlhaus", "listed": False,
                          "details": {"query_status": "no_results"}},
        ):
            result = await analyze("https://old.example.com/login")

            # Nessuna evidenza domain_age per domini vecchi
            age_ev = [e for e in result["evidence"] if e["key"] == "domain_age_days"]
            assert len(age_ev) == 0
            assert result["passive_risk_score"] == 0.0
