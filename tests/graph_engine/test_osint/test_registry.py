"""Tests per il registro provider di reputazione.

URLhaus è condizionale alla configurazione centralizzata: in un
ambiente pulito la lista è vuota.  MISP/OpenCTI non fanno più parte
del motore (gestiti a monte dal servizio chiamante).
"""

from __future__ import annotations

from graph_engine.config import settings
from graph_engine.osint.reputation.registry import get_enabled_providers
from graph_engine.osint.reputation.urlhaus import UrlhausProvider


def _provider_names() -> list[str]:
    return [p._provider for p in get_enabled_providers()]


class TestRegistry:
    def test_no_config_returns_empty_list(self, monkeypatch):
        """Senza alcuna variabile → nessun provider attivo."""
        monkeypatch.setattr(settings, "urlhaus_api_key", None)

        assert get_enabled_providers() == []

    def test_urlhaus_present_only_when_key_configured(self, monkeypatch):
        """URLhaus è condizionale: con la Auth-Key è presente,
        senza non compare nella lista."""
        monkeypatch.setattr(settings, "urlhaus_api_key", None)
        assert "urlhaus" not in _provider_names()

        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")
        assert _provider_names() == ["urlhaus"]

    def test_urlhaus_instance_receives_configured_key(self, monkeypatch):
        """Il provider istanziato dal registry legge la chiave dal
        singleton al momento della costruzione."""
        monkeypatch.setattr(settings, "urlhaus_api_key", "test-key")

        providers = get_enabled_providers()
        assert len(providers) == 1
        assert isinstance(providers[0], UrlhausProvider)
        assert providers[0]._api_key == "test-key"
