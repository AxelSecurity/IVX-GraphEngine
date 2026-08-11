"""Test d'integrazione reale — API pubbliche su dominio noto stabile.

Questi test richiedono RETE e sono marcati ``@pytest.mark.integration``.
NON vengono eseguiti dalla suite predefinita (``pytest.ini: addopts = -m "not integration"``).
Servono a beccare cambi di formato delle API reali nel tempo.

Esegui con::

    pytest -m integration tests/graph_engine/test_osint/test_integration_real.py
"""

from __future__ import annotations

import pytest


@pytest.mark.integration
class TestRealCertspotter:
    """crt.sh su un dominio noto con molti certificati (google.com)."""

    async def test_crtsh_real_returns_certificates(self):
        """crt.sh su google.com deve restituire certificati o errore trasparente."""
        import httpx
        from graph_engine.osint.certificate_transparency import query_crtsh

        async with httpx.AsyncClient() as client:
            result = await query_crtsh("google.com", client)

        # Accetta sia successo che errori transitori (es. 502 Bad Gateway)
        # — il formato della risposta è ciò che ci interessa
        if "error" in result:
            pytest.skip(f"crt.sh temporaneamente non disponibile: {result['error']}")
            return

        assert result["total_certs"] > 0, "Nessun certificato trovato per google.com"
        assert result["total_siblings"] > 0
        assert isinstance(result["sibling_domains"], list)
        assert "google.com" not in result["sibling_domains"]
        assert result["newest_cert_days"] is not None
        assert result["oldest_cert_days"] is not None


@pytest.mark.integration
class TestRealRdap:
    """RDAP su un dominio noto, stabile e longevo (google.com)."""

    async def test_rdap_real_returns_data(self):
        """RDAP su google.com deve restituire età, registrar."""
        import httpx
        from graph_engine.osint.rdap import query_rdap

        async with httpx.AsyncClient() as client:
            result = await query_rdap("google.com", client)

        if "error" in result:
            pytest.skip(f"RDAP temporaneamente non disponibile: {result['error']}")
            return

        # google.com esiste da decenni
        assert result["domain_age_days"] is not None
        assert result["domain_age_days"] > 365  # più di un anno
        assert len(result["nameservers"]) > 0


@pytest.mark.integration
class TestRealUrlhaus:
    """URLhaus su URL nota — verifichiamo solo che l'API risponda.

    Nota (2026-08): l'API URLhaus ora restituisce 401 Unauthorized —
    potrebbe richiedere autenticazione. Il nostro provider gestisce
    correttamente questa risposta come errore, senza crash.
    """

    async def test_urlhaus_real_no_results_for_google(self):
        """google.com non dovrebbe essere nel feed URLhaus."""
        import httpx
        from graph_engine.osint.reputation.urlhaus import UrlhausProvider

        async with httpx.AsyncClient() as client:
            provider = UrlhausProvider()
            result = await provider.check("https://www.google.com", client)

        assert result["provider"] == "urlhaus"
        # Accetta sia no_results (API funzionante) che error (es. 401 auth)
        # — il provider non deve mai crashare
        if "error" in result.get("details", {}):
            pytest.skip(
                f"URLhaus API non disponibile (possibile cambiamento auth): "
                f"{result['details']['error'][:100]}"
            )
            return

        assert result["listed"] is False
        assert result["details"].get("query_status") == "no_results"
