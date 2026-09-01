"""Fixture condivise per i test del wrapper Trellix.

Oltre all'app col db isolato, il conftest configura la API key di
default: la route Trellix è OBBLIGATORIAMENTE protetta (503 senza
chiave), quindi ogni test la trova impostata a ``test-key`` e il client
la invia nell'header ``X-API-Key``.  I test di auth la sovrascrivono
esplicitamente via monkeypatch per i casi 503/401.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.api.app import create_app
from graph_engine.config import settings


@pytest.fixture(autouse=True)
def _trellix_test_key(_isolate_config_from_environment, monkeypatch):
    """API key di default per la route Trellix nei test.

    Dipende esplicitamente dall'isolamento della configurazione (root
    conftest) così l'ordine è garantito: prima i campi vengono azzerati,
    poi qui si imposta la chiave di test.  Il monkeypatch la ripristina
    a fine test.
    """
    monkeypatch.setattr(settings, "trellix_api_key", "test-key")
    monkeypatch.setattr(settings, "trellix_api_token", None)


@pytest.fixture
def app(tmp_path):
    """App FastAPI con db isolato in tmp_path."""
    return create_app(
        db_path=str(tmp_path / "test.db"),
        artifact_root=tmp_path / "artifacts",
    )


@pytest.fixture
async def client(app):
    """Client httpx con ASGITransport e X-API-Key di test."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": "test-key"},
    ) as c:
        yield c
