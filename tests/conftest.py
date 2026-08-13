"""Pytest configuration — markers defined in pytest.ini.

Include anche la fixture globale di isolamento della configurazione
centralizzata (vedi sotto).
"""

from __future__ import annotations

import pytest

from graph_engine.config import settings

# Tutti i campi del Settings centralizzato (vedi graph_engine/config.py).
# Tenere allineato quando si aggiunge un nuovo campo lì.
_ALL_CONFIG_FIELDS = (
    "azure_foundry_endpoint",
    "azure_foundry_agent_id",
    "misp_url",
    "misp_api_key",
    "opencti_url",
    "opencti_api_key",
    "urlhaus_api_key",
    "trellix_api_token",
)


@pytest.fixture(autouse=True)
def _isolate_config_from_environment():
    """Isola la configurazione centralizzata dall'ambiente reale.

    Il singleton ``graph_engine.config.settings`` viene creato
    all'import e legge le variabili d'ambiente del processo (o
    ``.env``): se lo sviluppatore ha ``AZURE_FOUNDRY_*``,
    ``MISP_*``, ``OPENCTI_*`` o ``TRELLIX_API_TOKEN`` esportate nella
    propria shell, alcuni test fallirebbero in modo dipendente dalla
    macchina — es. le route Trellix richiederebbero auth Bearer (401)
    o il registro L2 attiverebbe provider reali (chiamate di rete).

    Prima di ogni test tutti i campi vengono azzerati; al termine
    vengono ripristinati ai valori originali.  Stesso principio della
    cache OSINT (``_CACHE_ROOT`` nei conftest locali), ma a livello
    dell'intera suite perché la configurazione è trasversale a tutti
    i moduli.

    I test che verificano la configurazione stessa
    (``tests/graph_engine/test_config.py``) istanziano ``Settings``
    direttamente con ``_env_file=None`` e non sono toccati da questa
    fixture.
    """
    original = {
        field: getattr(settings, field) for field in _ALL_CONFIG_FIELDS
    }
    for field in _ALL_CONFIG_FIELDS:
        setattr(settings, field, None)
    yield
    for field, value in original.items():
        setattr(settings, field, value)
