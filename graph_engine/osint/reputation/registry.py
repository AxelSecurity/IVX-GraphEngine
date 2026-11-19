"""Registro provider di reputazione.

Determina quali provider sono attivi in base alla configurazione
centralizzata (``graph_engine.config``).  Oggi l'unico provider è
URLhaus, disabilitato senza Auth-Key.  Le lookup verso piattaforme
di threat intelligence interne (MISP/OpenCTI) NON fanno parte del
motore: sono gestite a monte dal servizio chiamante.
"""

from __future__ import annotations

from graph_engine.config import settings
from graph_engine.osint.reputation.base import ReputationProvider
from graph_engine.osint.reputation.urlhaus import UrlhausProvider


def get_enabled_providers() -> list[ReputationProvider]:
    """Restituisce la lista dei provider di reputazione abilitati.

    URLhaus viene aggiunto solo se la Auth-Key (``URLHAUS_API_KEY``)
    è configurata.
    """
    providers: list[ReputationProvider] = []

    # URLhaus — richiede URLHAUS_API_KEY (Auth-Key gratuita abuse.ch)
    if settings.urlhaus_configured:
        providers.append(UrlhausProvider())

    return providers
