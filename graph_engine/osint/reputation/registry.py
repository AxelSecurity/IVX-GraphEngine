"""Registro provider di reputazione L2.

Oggi nessun provider è attivo: le lookup su feed e piattaforme di
threat intelligence (MISP, OpenCTI, URLhaus) NON fanno parte del motore
e sono gestite a monte dal servizio chiamante.  L'interfaccia resta
pronta: un futuro provider implementa ``ReputationProvider.check()``
(vedi ``base.py``) e viene aggiunto qui, condizionato alla propria
configurazione in ``graph_engine.config``; ``osint.analyzer`` ne
trasforma già i risultati in evidenze (``reputation_hit``,
``provider_unavailable``).
"""

from __future__ import annotations

from graph_engine.osint.reputation.base import ReputationProvider


def get_enabled_providers() -> list[ReputationProvider]:
    """Restituisce la lista dei provider di reputazione abilitati."""
    return []
