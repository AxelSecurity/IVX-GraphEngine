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
            await analyze("https://old.example.com/login", timeout_s=5.0)

        assert _RecordingAsyncClient.created == [{"timeout": 5.0}]

        _RecordingAsyncClient.created = []
        with patch(
            "graph_engine.osint.analyzer.httpx.AsyncClient",
            _RecordingAsyncClient,
        ), patch(
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

    _CRTSH_CLEAN = {
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

    async def _analyze(self, monkeypatch, crtsh_result, rdap_result,
                       dns_result, urlhaus_result):
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value=crtsh_result,
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
            self._CRTSH_CLEAN,
            self._RDAP_YOUNG,
            self._DNS_CLEAN,
            self._URLHAUS_CLEAN,
        )
        self._assert_score_equals_weight_sum(result)
        assert result["passive_risk_score"] == 0.35

    async def test_young_plus_siblings(self, monkeypatch):
        """Young + siblings (0.35 + 0.30) → score == somma."""
        crtsh = {
            "sibling_domains": ["sib1.example.com", "sib2.example.com"],
            "truncated": False, "total_siblings": 2,
            "newest_cert_days": 30, "oldest_cert_days": 60, "total_certs": 3,
        }
        result = await self._analyze(
            monkeypatch, crtsh, self._RDAP_YOUNG,
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
            monkeypatch, self._CRTSH_CLEAN, self._RDAP_MODERATE,
            self._DNS_CLEAN, urlhaus_hit,
        )
        self._assert_score_equals_weight_sum(result)
        assert result["passive_risk_score"] == 0.65

    async def test_sum_exceeding_one_still_clamped(self, monkeypatch):
        """Somma > 1.0 → la proprietà vale salvo clamp (score == 1.0)."""
        crtsh = {
            "sibling_domains": ["sib.example.com"],
            "truncated": False, "total_siblings": 1,
            "newest_cert_days": 30, "oldest_cert_days": 60, "total_certs": 3,
        }
        urlhaus_hit = {
            "provider": "urlhaus", "listed": True,
            "details": {"threat": "phishing"},
        }
        result = await self._analyze(
            monkeypatch, crtsh, self._RDAP_YOUNG,
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
        crtsh_error = {"error": "crt.sh down"}
        result = await self._analyze(
            monkeypatch, crtsh_error, self._RDAP_YOUNG,
            self._DNS_CLEAN, self._URLHAUS_CLEAN,
        )
        self._assert_score_equals_weight_sum(result)
        # Solo young (0.35): provider_unavailable e dns_a_records sono 0.0
        assert result["passive_risk_score"] == 0.35


class TestDnsFirstSequencing:
    """La nuova orchestrazione L2: DNS PRIMA, poi crt.sh/RDAP/
    reputation in parallelo — con gli IP risolti passati ai provider.

    La sequenzialità è voluta (gli IP alimentano la query MISP per
    ``ip-dst``) e va verificata con un handshake deterministico:
    le fonti successive devono partire SOLO a DNS completato.
    """

    _CRTSH_CLEAN = {
        "sibling_domains": [], "truncated": False, "total_siblings": 0,
        "newest_cert_days": None, "oldest_cert_days": None, "total_certs": 0,
    }
    _RDAP_OLD = {"domain_age_days": 365, "registrar": "R", "nameservers": []}
    _URLHAUS_CLEAN = {
        "provider": "urlhaus", "listed": False,
        "details": {"query_status": "no_results"},
    }

    async def test_dns_resolved_before_other_sources_start(self, monkeypatch):
        """crtsh/RDAP/reputation devono partire SOLO dopo che il DNS è
        completato (handshake con asyncio.Event: deterministico, non
        basato sul caso)."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        dns_done = asyncio.Event()

        async def dns_then_set(*args, **kwargs):
            try:
                return {
                    "a_records": ["1.2.3.4"], "aaaa_records": [],
                    "error": None,
                }
            finally:
                dns_done.set()

        async def assert_dns_done(*args, **kwargs):
            assert dns_done.is_set(), (
                "fonte partita PRIMA che la risoluzione DNS finisse — "
                "la sequenza DNS-prima-poi-resto è rotta"
            )
            return {"sibling_domains": [], "truncated": False,
                    "total_siblings": 0, "newest_cert_days": None,
                    "oldest_cert_days": None, "total_certs": 0}

        with patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            side_effect=dns_then_set,
        ), patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            side_effect=assert_dns_done,
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            side_effect=assert_dns_done,
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            side_effect=assert_dns_done,
        ):
            result = await analyze("https://evil.example.com/login")

        assert "evidence" in result

    async def test_known_ips_forwarded_to_reputation_providers(self, monkeypatch):
        """Gli IP risolti (A + AAAA, filtrati dai valori sporchi)
        devono arrivare come ``known_ips`` al check dei provider."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value=self._CRTSH_CLEAN,
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value=self._RDAP_OLD,
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={
                # None e stringa vuota: sporcizia da filtrare
                "a_records": ["93.184.216.34", "", None],
                "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
                "error": None,
            },
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value=self._URLHAUS_CLEAN,
        ) as mock_urlhaus:
            await analyze("https://evil.example.com/login")

        mock_urlhaus.assert_called_once()
        assert mock_urlhaus.call_args.kwargs["known_ips"] == [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
        ]

    async def test_dns_failure_gives_empty_known_ips(self, monkeypatch):
        """DNS in errore → known_ips lista vuota (mai None): i provider
        ricevono comunque il parametro."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        with patch(
            "graph_engine.osint.analyzer.query_crtsh",
            new_callable=AsyncMock,
            return_value=self._CRTSH_CLEAN,
        ), patch(
            "graph_engine.osint.analyzer.query_rdap",
            new_callable=AsyncMock,
            return_value=self._RDAP_OLD,
        ), patch(
            "graph_engine.osint.analyzer.resolve_dns",
            new_callable=AsyncMock,
            return_value={
                "a_records": [], "aaaa_records": [],
                "error": "No DNS records found for evil.example.com",
            },
        ), patch(
            "graph_engine.osint.reputation.urlhaus.UrlhausProvider.check",
            new_callable=AsyncMock,
            return_value=self._URLHAUS_CLEAN,
        ) as mock_urlhaus:
            await analyze("https://evil.example.com/login")

        assert mock_urlhaus.call_args.kwargs["known_ips"] == []


class TestMispWeighting:
    """La ponderazione MISP nel risk score: hit reale (to_ids=true)
    pesa 0.55; match context-only (solo to_ids=false) pesa 0.0 ma
    resta visibile come evidenza informativa.

    MISP è l'unico provider abilitato (nessuna Auth-Key URLhaus) e
    le altre fonti sono patchate a valori neutri.
    """

    _CRTSH_CLEAN = {
        "sibling_domains": [], "truncated": False, "total_siblings": 0,
        "newest_cert_days": None, "oldest_cert_days": None, "total_certs": 0,
    }
    _RDAP_OLD = {"domain_age_days": 365, "registrar": "R", "nameservers": []}
    _DNS_CLEAN = {"a_records": ["1.2.3.4"], "aaaa_records": [], "error": None}

    @staticmethod
    def _patch_neutral_sources():
        """crt.sh/RDAP/DNS patchati a risultati senza segnale."""
        return [
            patch(
                "graph_engine.osint.analyzer.query_crtsh",
                new_callable=AsyncMock,
                return_value=TestMispWeighting._CRTSH_CLEAN,
            ),
            patch(
                "graph_engine.osint.analyzer.query_rdap",
                new_callable=AsyncMock,
                return_value=TestMispWeighting._RDAP_OLD,
            ),
            patch(
                "graph_engine.osint.analyzer.resolve_dns",
                new_callable=AsyncMock,
                return_value=TestMispWeighting._DNS_CLEAN,
            ),
        ]

    async def test_to_ids_hit_weights_high(self, monkeypatch):
        """Hit MISP con to_ids_match → reputation_hit a peso 0.55
        (leggermente sopra il 0.50 dei feed automatizzati)."""
        monkeypatch.setattr(settings, "misp_url", "https://misp.example")
        monkeypatch.setattr(settings, "misp_api_key", "test-key")

        misp_hit = {
            "provider": "misp",
            "listed": True,
            "details": {
                "match_count": 2,
                "matched_types": ["domain", "ip-dst"],
                "tags": ["phishing"],
                "event_count": 2,
                "to_ids_match": True,
                "context_only": False,
            },
        }

        with ExitStack() as stack:
            for pm in self._patch_neutral_sources():
                stack.enter_context(pm)
            stack.enter_context(patch(
                "graph_engine.osint.reputation.misp.MispProvider.check",
                new_callable=AsyncMock,
                return_value=misp_hit,
            ))
            result = await analyze("https://evil.example.com/login")

        hit_ev = [e for e in result["evidence"] if e["key"] == "reputation_hit"]
        assert len(hit_ev) == 1
        assert hit_ev[0]["weight"] == 0.55
        assert result["passive_risk_score"] == 0.55

    async def test_context_only_match_zero_weight(self, monkeypatch):
        """Match MISP solo to_ids=false → evidenza ``misp_context_match``
        informativa a peso 0.0: nessuna penalizzazione."""
        monkeypatch.setattr(settings, "misp_url", "https://misp.example")
        monkeypatch.setattr(settings, "misp_api_key", "test-key")

        misp_context = {
            "provider": "misp",
            "listed": False,
            "details": {
                "match_count": 3,
                "matched_types": ["domain"],
                "tags": ["tlp:white"],
                "event_count": 1,
                "to_ids_match": False,
                "context_only": True,
            },
        }

        with ExitStack() as stack:
            for pm in self._patch_neutral_sources():
                stack.enter_context(pm)
            stack.enter_context(patch(
                "graph_engine.osint.reputation.misp.MispProvider.check",
                new_callable=AsyncMock,
                return_value=misp_context,
            ))
            result = await analyze("https://evil.example.com/login")

        ctx_ev = [
            e for e in result["evidence"]
            if e["key"] == "misp_context_match"
        ]
        assert len(ctx_ev) == 1
        assert ctx_ev[0]["weight"] == 0.0
        # Nessuna reputation_hit: un context_only NON è un hit
        assert not [
            e for e in result["evidence"] if e["key"] == "reputation_hit"
        ]
        # Dominio vecchio → unico segnale possibile era MISP: score 0
        assert result["passive_risk_score"] == 0.0


class TestOpenCtiWeighting:
    """La ponderazione OpenCTI nel risk score: IOC attivo (non revoked,
    non scaduto) pesa 0.55 come il MISP to_ids; match context-only
    (osservabile senza Indicator attivo) pesa 0.0 ma resta visibile
    come evidenza informativa ``opencti_context_match``.

    OpenCTI è l'unico provider abilitato (MISP e URLhaus non
    configurati) e le altre fonti sono patchate a valori neutri.
    """

    _CRTSH_CLEAN = {
        "sibling_domains": [], "truncated": False, "total_siblings": 0,
        "newest_cert_days": None, "oldest_cert_days": None, "total_certs": 0,
    }
    _RDAP_OLD = {"domain_age_days": 365, "registrar": "R", "nameservers": []}
    _DNS_CLEAN = {"a_records": ["1.2.3.4"], "aaaa_records": [], "error": None}

    @staticmethod
    def _patch_neutral_sources():
        """crt.sh/RDAP/DNS patchati a risultati senza segnale."""
        return [
            patch(
                "graph_engine.osint.analyzer.query_crtsh",
                new_callable=AsyncMock,
                return_value=TestOpenCtiWeighting._CRTSH_CLEAN,
            ),
            patch(
                "graph_engine.osint.analyzer.query_rdap",
                new_callable=AsyncMock,
                return_value=TestOpenCtiWeighting._RDAP_OLD,
            ),
            patch(
                "graph_engine.osint.analyzer.resolve_dns",
                new_callable=AsyncMock,
                return_value=TestOpenCtiWeighting._DNS_CLEAN,
            ),
        ]

    async def test_active_ioc_hit_weights_high(self, monkeypatch):
        """Hit OpenCTI con IOC attivo → reputation_hit a peso 0.55
        (come il MISP to_ids: segnale malevolo verificato)."""
        monkeypatch.setattr(settings, "opencti_url", "https://opencti.example")
        monkeypatch.setattr(settings, "opencti_api_key", "test-key")

        opencti_hit = {
            "provider": "opencti",
            "listed": True,
            "details": {
                "match_count": 1,
                "matched_types": ["Url"],
                "active_indicator_count": 1,
                "total_indicator_count": 1,
                "labels": ["phishing"],
                "markings": ["TLP:AMBER"],
                "created_by": ["CERT-AGID"],
                "score_min": 85,
                "score_max": 85,
                "score_avg": 85.0,
                "active_ioc_match": True,
                "context_only": False,
            },
        }

        with ExitStack() as stack:
            for pm in self._patch_neutral_sources():
                stack.enter_context(pm)
            stack.enter_context(patch(
                "graph_engine.osint.reputation.opencti.OpenCtiProvider.check",
                new_callable=AsyncMock,
                return_value=opencti_hit,
            ))
            result = await analyze("https://evil.example.com/login")

        hit_ev = [e for e in result["evidence"] if e["key"] == "reputation_hit"]
        assert len(hit_ev) == 1
        assert hit_ev[0]["weight"] == 0.55
        assert result["passive_risk_score"] == 0.55

    async def test_context_only_match_zero_weight(self, monkeypatch):
        """Osservabile OpenCTI senza IOC attivo → evidenza
        ``opencti_context_match`` informativa a peso 0.0: nessuna
        penalizzazione e NESSUNA chiave misp_context_match spuria."""
        monkeypatch.setattr(settings, "opencti_url", "https://opencti.example")
        monkeypatch.setattr(settings, "opencti_api_key", "test-key")

        opencti_context = {
            "provider": "opencti",
            "listed": False,
            "details": {
                "match_count": 1,
                "matched_types": ["Domain-Name"],
                "active_indicator_count": 0,
                "total_indicator_count": 1,
                "labels": [],
                "markings": [],
                "created_by": ["Sconosciuti"],
                "score_min": None,
                "score_max": None,
                "score_avg": None,
                "active_ioc_match": False,
                "context_only": True,
            },
        }

        with ExitStack() as stack:
            for pm in self._patch_neutral_sources():
                stack.enter_context(pm)
            stack.enter_context(patch(
                "graph_engine.osint.reputation.opencti.OpenCtiProvider.check",
                new_callable=AsyncMock,
                return_value=opencti_context,
            ))
            result = await analyze("https://evil.example.com/login")

        ctx_ev = [
            e for e in result["evidence"]
            if e["key"] == "opencti_context_match"
        ]
        assert len(ctx_ev) == 1
        assert ctx_ev[0]["weight"] == 0.0
        # Nessuna reputation_hit: un context_only NON è un hit
        assert not [
            e for e in result["evidence"] if e["key"] == "reputation_hit"
        ]
        # La chiave MISP non deve comparire per un match OpenCTI
        assert not [
            e for e in result["evidence"] if e["key"] == "misp_context_match"
        ]
        assert result["passive_risk_score"] == 0.0
