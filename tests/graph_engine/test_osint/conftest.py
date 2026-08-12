"""Fixture condivise per il package test_osint."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_osint_cache(tmp_path, monkeypatch):
    """Isola la cache filesystem OSINT in una directory temporanea.

    Ogni test nel package ``test_osint/`` usa automaticamente una cache
    isolata, evitando contaminazioni cross-esecuzione. Prima di questa
    fixture, diversi test scrivevano nella cache reale
    ``data/osint_cache/`` e le esecuzioni successive leggevano dati
    stantii (es. ``test_unexpected_exception_logged_and_marked``:
    ``cache_get`` restituiva il risultato cachato dalla prima run,
    saltando completamente ``logger.exception()`` e rendendo vuoti
    gli assert ``caplog``).

    I test che già isolano esplicitamente la cache (``TestDnsCache``,
    ``test_cache.py``) non sono influenzati: la loro impostazione
    semplicemente prevale su questa.

    I test di integrazione (``test_integration_real.py``) usano
    anch'essi la cache isolata — non vogliamo che una cache reale
    stantia interferisca nemmeno lì.
    """
    monkeypatch.setattr(
        "graph_engine.osint.cache._CACHE_ROOT",
        tmp_path / "osint_cache",
    )
