"""Registro provider di reputazione.

Determina quali provider sono attivi in base alla configurazione
centralizzata (``graph_engine.config``).
Oggi, in un ambiente pulito, la lista è vuota: URLhaus, MISP e
OpenCTI sono tutti predisposti ma disabilitati senza configurazione.
"""

from __future__ import annotations

from graph_engine.config import settings
from graph_engine.osint.reputation.base import ReputationProvider
from graph_engine.osint.reputation.urlhaus import UrlhausProvider


def get_enabled_providers() -> list[ReputationProvider]:
    """Restituisce la lista dei provider di reputazione abilitati.

    URLhaus viene aggiunto solo se la Auth-Key (``URLHAUS_API_KEY``)
    è configurata.  MISP e OpenCTI vengono aggiunti solo se le
    rispettive coppie di variabili sono configurate.
    """
    providers: list[ReputationProvider] = []

    # URLhaus — richiede URLHAUS_API_KEY (Auth-Key gratuita abuse.ch)
    if settings.urlhaus_configured:
        providers.append(UrlhausProvider())

    # MISP — richiede MISP_URL + MISP_API_KEY
    if settings.misp_configured:
        from graph_engine.osint.reputation.misp import MispProvider

        providers.append(MispProvider())

    # OpenCTI — richiede OPENCTI_URL + OPENCTI_API_KEY
    if settings.opencti_configured:
        from graph_engine.osint.reputation.opencti import OpenCtiProvider

        providers.append(OpenCtiProvider())

    return providers
