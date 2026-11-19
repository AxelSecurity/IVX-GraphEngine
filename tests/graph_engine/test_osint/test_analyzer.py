"""Tests d'integrazione per l'analyzer L2."""

from __future__ import annotations

import asyncio
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

from graph_engine.config import settings
from graph_engine.osint.analyzer import analyze


class _RecordingAsyncClient:
    """Fake context manager al posto di ``httpx.AsyncClient`` — registra
    i kwargs del costruttore così i test possono ispezionare il timeout
    (ceiling del client condiviso)."""

    created: list[dict] = []

    def __init__(self, **kwargs):
        type(self).created.append(kwargs)
        self.client = MagicMock()

    async def __aenter__(self):
        return self.client

    async def __aexit__(self, exc_type, exc, tb):
        return False


class TestAnalyzerIntegration:
    async def test_all_sources_in_parallel(self, monkeypatch):
        """Verifica che le fonti vengano chiamate (anche se mockate)."""
        # URLhaus è condizionale alla Auth-Key: la configuriamo perché
        # il registry lo includa tra i provider abilitati.
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        # Per questo test, mockiamo direttamente le tre funzioni di query
        # per evitare di dover mockare httpx a più livelli
        with patch(
            "graph_engine.osint.analyzer.query_ctlogs",
            new_callable=AsyncMock,
        ) as mock_ctlogs, patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
        ) as mock_rdap, patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
        ) as mock_dns, patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
        ) as mock_urlhaus:

            mock_ctlogs.return_value = {
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
            mock_ctlogs.assert_called_once()
            mock_rdap.assert_called_once()
            mock_dns.assert_called_once()
            mock_urlhaus.assert_called_once()

    async def test_one_source_failure_doesnt_block_others(self, monkeypatch):
        """Se una fonte fallisce, le altre producono comunque risultati."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_ctlogs",
            new_callable=AsyncMock,
        ) as mock_ctlogs, patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
        ) as mock_rdap, patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
        ) as mock_dns, patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
        ) as mock_urlhaus:

            # Il provider CT fallisce (eccezione catturata dal gather)
            mock_ctlogs.side_effect = RuntimeError("crash!")
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

            # Il provider CT deve aver fallito → evidenza provider_unavailable
            unavail = [
                e for e in result["evidence"]
                if e["key"] == "provider_unavailable" and "ctlogs" in str(e["value"])
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
            "graph_engine.osint.analyzer.query_ctlogs",
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
            "graph_engine.osint.analyzer.query_ctlogs",
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
            "graph_engine.osint.analyzer.query_ctlogs",
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
            "graph_engine.osint.analyzer.query_ctlogs",
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
            "graph_engine.osint.analyzer.query_ctlogs",
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

    async def test_client_timeout_follows_timeout_s(self, monkeypatch):
        """Il ceiling del client HTTP condiviso segue ``timeout_s``:
        ``analyze(url, timeout_s=5.0)`` costruisce il client con
        timeout 5.0 (fast path), senza parametro resta il default 30.0."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        _RecordingAsyncClient.created = []
        with patch(
            "graph_engine.osint.analyzer.httpx.AsyncClient",
            _RecordingAsyncClient,
        ), patch(
            "graph_engine.osint.analyzer.query_ctlogs",
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
            await analyze("https://old.example.com/login", timeout_s=5.0)

        assert _RecordingAsyncClient.created == [{"timeout": 5.0}]

        _RecordingAsyncClient.created = []
        with patch(
            "graph_engine.osint.analyzer.httpx.AsyncClient",
            _RecordingAsyncClient,
        ), patch(
            "graph_engine.osint.analyzer.query_ctlogs",
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
            await analyze("https://old.example.com/login")

        assert _RecordingAsyncClient.created == [{"timeout": 30.0}]


class TestRiskScoreDerivedFromWeights:
    """Proprietà strutturale: passive_risk_score È la somma dei weight
    delle Evidence prodotte (single source of truth).

    Non esiste un accumulo parallelo di ``risk`` accanto alla
    costruzione delle Evidence: se qualcuno reintroducesse due percorsi
    (es. ``risk += _W_X`` accanto a ``weight=_W_X``), questo test lo
    intercetterebbe per costruzione, non per coincidenza del valore
    atteso di un singolo caso.
    """

    _CTLOGS_CLEAN = {
        "sibling_domains": [], "truncated": False, "total_siblings": 0,
        "newest_cert_days": None, "oldest_cert_days": None, "total_certs": 0,
    }
    _RDAP_YOUNG = {"domain_age_days": 7, "registrar": "R", "nameservers": []}
    _RDAP_MODERATE = {"domain_age_days": 45, "registrar": "R", "nameservers": []}
    _DNS_CLEAN = {"a_records": ["1.2.3.4"], "aaaa_records": [], "error": None}
    _URLHAUS_CLEAN = {
        "provider": "urlhaus", "listed": False,
        "details": {"query_status": "no_results"},
    }

    async def _analyze(self, monkeypatch, ctlogs_result, rdap_result,
                       dns_result, urlhaus_result):
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_ctlogs",
            new_callable=AsyncMock,
            return_value=ctlogs_result,
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value=rdap_result,
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value=dns_result,
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value=urlhaus_result,
        ):
            return await analyze("https://evil.example.com/login")

    @staticmethod
    def _assert_score_equals_weight_sum(result):
        """Lo score deve essere esattamente la somma dei weight delle
        Evidence (unica trasformazione ammessa: il clamp a [0, 1])."""
        weight_sum = sum(ev["weight"] for ev in result["evidence"])
        assert result["passive_risk_score"] == round(
            min(1.0, weight_sum), 4
        )

    async def test_young_only(self, monkeypatch):
        """Young (0.35) → score == somma dei weight."""
        result = await self._analyze(
            monkeypatch,
            self._CTLOGS_CLEAN,
            self._RDAP_YOUNG,
            self._DNS_CLEAN,
            self._URLHAUS_CLEAN,
        )
        self._assert_score_equals_weight_sum(result)
        assert result["passive_risk_score"] == 0.35

    async def test_young_plus_siblings(self, monkeypatch):
        """Young + siblings (0.35 + 0.30) → score == somma."""
        ctlogs_result = {
            "sibling_domains": ["sib1.example.com", "sib2.example.com"],
            "truncated": False, "total_siblings": 2,
            "newest_cert_days": 30, "oldest_cert_days": 60, "total_certs": 3,
        }
        result = await self._analyze(
            monkeypatch, ctlogs_result, self._RDAP_YOUNG,
            self._DNS_CLEAN, self._URLHAUS_CLEAN,
        )
        self._assert_score_equals_weight_sum(result)
        assert result["passive_risk_score"] == 0.65

    async def test_moderate_plus_reputation(self, monkeypatch):
        """Moderate + reputation hit (0.15 + 0.50) → score == somma."""
        urlhaus_hit = {
            "provider": "urlhaus", "listed": True,
            "details": {"threat": "phishing"},
        }
        result = await self._analyze(
            monkeypatch, self._CTLOGS_CLEAN, self._RDAP_MODERATE,
            self._DNS_CLEAN, urlhaus_hit,
        )
        self._assert_score_equals_weight_sum(result)
        assert result["passive_risk_score"] == 0.65

    async def test_sum_exceeding_one_still_clamped(self, monkeypatch):
        """Somma > 1.0 → la proprietà vale salvo clamp (score == 1.0)."""
        ctlogs_result = {
            "sibling_domains": ["sib.example.com"],
            "truncated": False, "total_siblings": 1,
            "newest_cert_days": 30, "oldest_cert_days": 60, "total_certs": 3,
        }
        urlhaus_hit = {
            "provider": "urlhaus", "listed": True,
            "details": {"threat": "phishing"},
        }
        result = await self._analyze(
            monkeypatch, ctlogs_result, self._RDAP_YOUNG,
            self._DNS_CLEAN, urlhaus_hit,
        )
        self._assert_score_equals_weight_sum(result)
        # 0.30 + 0.35 + 0.50 = 1.15 → clampato
        assert result["passive_risk_score"] == 1.0

    async def test_informative_zero_weight_evidence_do_not_affect_sum(
        self, monkeypatch
    ):
        """Evidenze informative (provider_unavailable, dns_*) hanno
        weight=0.0 e non alterano la somma."""
        ctlogs_error = {"error": "ctlogs.dev down"}
        result = await self._analyze(
            monkeypatch, ctlogs_error, self._RDAP_YOUNG,
            self._DNS_CLEAN, self._URLHAUS_CLEAN,
        )
        self._assert_score_equals_weight_sum(result)
        # Solo young (0.35): provider_unavailable e dns_a_records sono 0.0
        assert result["passive_risk_score"] == 0.35


class TestParallelSources:
    """Orchestrazione L2: DNS, ctlogs.dev, RDAP e reputation partono
    TUTTI in parallelo — il DNS non è più uno stadio bloccante (serviva
    solo a passare gli IP a MISP, rimosso dal motore).
    """

    _CTLOGS_CLEAN = {
        "sibling_domains": [], "truncated": False, "total_siblings": 0,
        "newest_cert_days": None, "oldest_cert_days": None, "total_certs": 0,
    }
    _RDAP_OLD = {"domain_age_days": 365, "registrar": "R", "nameservers": []}
    _URLHAUS_CLEAN = {
        "provider": "urlhaus", "listed": False,
        "details": {"query_status": "no_results"},
    }

    async def test_dns_does_not_block_other_sources(self, monkeypatch):
        """Il DNS attende che ctlogs/RDAP/URLhaus siano GIÀ partiti:
        con un'orchestrazione sequenziale (DNS prima) questo test va
        in deadlock e scade il timeout (handshake deterministico)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        started = {"ctlogs": asyncio.Event(), "rdap": asyncio.Event(),
                   "urlhaus": asyncio.Event()}

        async def dns_waits_for_others(*args, **kwargs):
            for ev in started.values():
                await ev.wait()
            return {"a_records": ["1.2.3.4"], "aaaa_records": [], "error": None}

        def _mark(name, value):
            async def _inner(*args, **kwargs):
                started[name].set()
                return value
            return _inner

        with patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            side_effect=dns_waits_for_others,
        ), patch(
            "graph_engine.osint.analyzer.query_ctlogs",
            new_callable=AsyncMock,
            side_effect=_mark("ctlogs", self._CTLOGS_CLEAN),
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            side_effect=_mark("rdap", self._RDAP_OLD),
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            side_effect=_mark("urlhaus", self._URLHAUS_CLEAN),
        ):
            result = await asyncio.wait_for(
                analyze("https://evil.example.com/login"), timeout=2.0
            )

        keys = {e["key"] for e in result["evidence"]}
        assert "dns_a_records" in keys

    async def test_reputation_provider_called_with_url_only(self, monkeypatch):
        """I provider ricevono URL, client e timeout — niente IP."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_ctlogs",
            new_callable=AsyncMock,
            return_value=self._CTLOGS_CLEAN,
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value=self._RDAP_OLD,
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={"a_records": [], "aaaa_records": [], "error": None},
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value=self._URLHAUS_CLEAN,
        ) as mock_urlhaus:
            await analyze("https://evil.example.com/login")

        mock_urlhaus.assert_called_once()
        assert "known_ips" not in mock_urlhaus.call_args.kwargs


class TestCtlogsEvidence:
    """ctlogs.dev come UNICO provider CT (crt.sh rimosso il 2026-08-27).

    Due modalità decise dal provider: API (con CTLOGS_API_KEY →
    ``sibling_domains``) e anonima (senza chiave → ``certificate_history``
    senza sibling).  Un errore del provider produce ``provider_unavailable``
    informativo (weight 0.0) e nessuna evidenza CT.
    """

    def _patch_l2_sources(self, ctlogs_side_effect=None):
        """Patch di query_ctlogs + RDAP + DNS + URLhaus, restituisce i mock."""
        from graph_engine.osint.analyzer import (
            query_ctlogs,
            query_rdap,
            resolve_dns,
        )
        from graph_engine.osint.reputation.urlhaus import UrlhausProvider

        mock_ctlogs = AsyncMock(side_effect=ctlogs_side_effect)
        mock_rdap = AsyncMock(return_value={
            "domain_age_days": 2000,  # vecchio → peso 0.0, non disturba
            "registrar": "TestReg",
            "nameservers": [],
        })
        mock_dns = AsyncMock(return_value={
            "a_records": ["1.2.3.4"],
            "aaaa_records": [],
            "error": None,
        })
        mock_urlhaus = AsyncMock(return_value={
            "provider": "urlhaus",
            "listed": False,
            "details": {"query_status": "no_results"},
        })

        return (
            patch("graph_engine.osint.analyzer.query_ctlogs", mock_ctlogs),
            patch("graph_engine.osint.analyzer.query_rdap", mock_rdap),
            patch("graph_engine.osint.analyzer.resolve_dns", mock_dns),
            patch.object(UrlhausProvider, "check", mock_urlhaus),
            mock_ctlogs,
        )

    async def test_sibling_evidence_with_key(self, monkeypatch):
        """Sibling dal provider → sibling_domains weight 0.30, source
        ctlogs.dev; nessuna certificate_history."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", "test-key")
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources()
        )
        mock_ctlogs.return_value = {
            "sibling_domains": ["sib.example.com"],
            "truncated": False,
            "total_siblings": 1,
            "newest_cert_days": 2,
            "oldest_cert_days": None,
            "total_certs": None,
            "source": "ctlogs.dev",
            "mode": "api",
        }

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        siblings = [
            e for e in result["evidence"] if e["key"] == "sibling_domains"
        ]
        assert len(siblings) == 1
        assert siblings[0]["value"]["domains"] == ["sib.example.com"]
        assert siblings[0]["value"]["source"] == "ctlogs.dev"
        assert siblings[0]["weight"] == 0.30
        assert not [
            e for e in result["evidence"]
            if e["key"] == "certificate_history"
        ]
        assert result["passive_risk_score"] == 0.30

    async def test_provider_error_adds_unavailable(self, monkeypatch):
        """Errore del provider → provider_unavailable ctlogs.dev
        (informativo), nessuna evidenza sibling/certificate."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", "test-key")
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources()
        )
        mock_ctlogs.return_value = {"error": "ctlogs.dev HTTP error: 404"}

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        unavail = [
            e for e in result["evidence"]
            if e["key"] == "provider_unavailable"
        ]
        providers = {u["value"]["provider"] for u in unavail}
        assert providers == {"ctlogs.dev"}
        assert unavail[0]["weight"] == 0.0
        assert not [
            e for e in result["evidence"] if e["key"] == "sibling_domains"
        ]
        assert not [
            e for e in result["evidence"]
            if e["key"] == "certificate_history"
        ]
        assert result["passive_risk_score"] == 0.0

    async def test_anonymous_certificate_history(self, monkeypatch):
        """Senza sibling ma con cronologia → certificate_history; cert
        fresco (≤30 giorni) pesato 0.15."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources()
        )
        mock_ctlogs.return_value = {
            "sibling_domains": [],
            "truncated": False,
            "total_siblings": 0,
            "newest_cert_days": 5,
            "oldest_cert_days": 90,
            "total_certs": 2,
            "source": "ctlogs.dev",
            "mode": "anonymous",
        }

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        hist = [
            e for e in result["evidence"] if e["key"] == "certificate_history"
        ]
        assert len(hist) == 1
        assert hist[0]["value"]["source"] == "ctlogs.dev"
        assert hist[0]["value"]["mode"] == "anonymous"
        assert hist[0]["value"]["newest_cert_days"] == 5
        assert hist[0]["weight"] == 0.15  # cert di 5 giorni → fresh
        assert result["passive_risk_score"] == 0.15

    async def test_old_cert_history_informative(self, monkeypatch):
        """Cronologia con cert vecchio → certificate_history weight 0.0
        (informativa — mai penalizzare per assenza di segnale)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources()
        )
        mock_ctlogs.return_value = {
            "sibling_domains": [],
            "truncated": False,
            "total_siblings": 0,
            "newest_cert_days": 400,
            "oldest_cert_days": 500,
            "total_certs": 3,
            "source": "ctlogs.dev",
            "mode": "anonymous",
        }

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        hist = [
            e for e in result["evidence"] if e["key"] == "certificate_history"
        ]
        assert len(hist) == 1
        assert hist[0]["weight"] == 0.0
        assert result["passive_risk_score"] == 0.0

    async def test_no_cert_history_when_newest_unknown(self, monkeypatch):
        """Sibling vuoti E newest ignoto → nessuna evidenza CT
        (niente da dire senza cronologia, mai inventare)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", None)
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources()
        )
        mock_ctlogs.return_value = {
            "sibling_domains": [],
            "truncated": False,
            "total_siblings": 0,
            "newest_cert_days": None,
            "oldest_cert_days": None,
            "total_certs": 0,
            "source": "ctlogs.dev",
            "mode": "anonymous",
        }

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        assert not [
            e for e in result["evidence"]
            if e["key"] == "certificate_history"
        ]
        assert not [
            e for e in result["evidence"] if e["key"] == "sibling_domains"
        ]
        assert result["passive_risk_score"] == 0.0

    async def test_exception_from_gather_adds_unavailable(
        self, monkeypatch
    ):
        """Il provider LANCIA (eccezione catturata dal gather) →
        provider_unavailable ctlogs.dev, mai crash."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        monkeypatch.setattr(settings, "ctlogs_api_key", "test-key")
        p_ctlogs, p_rdap, p_dns, p_urlhaus, mock_ctlogs = (
            self._patch_l2_sources(ctlogs_side_effect=RuntimeError("crash!"))
        )

        with p_ctlogs, p_rdap, p_dns, p_urlhaus:
            result = await analyze("https://evil.example.com/login")

        unavail = [
            e for e in result["evidence"]
            if e["key"] == "provider_unavailable"
        ]
        providers = {u["value"]["provider"] for u in unavail}
        assert providers == {"ctlogs.dev"}
        assert result["passive_risk_score"] == 0.0
