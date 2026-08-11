"""Registro provider di reputazione.

Determina quali provider sono attivi in base alle variabili d'ambiente.
Oggi, in un ambiente pulito, la lista contiene solo URLhaus.
"""

from __future__ import annotations

import os

from graph_engine.osint.reputation.base import ReputationProvider
from graph_engine.osint.reputation.urlhaus import UrlhausProvider


def get_enabled_providers() -> list[ReputationProvider]:
    """Restituisce la lista dei provider di reputazione abilitati.

    URLhaus è sempre attivo (API gratuita, nessuna chiave).
    MISP e OpenCTI vengono aggiunti solo se le rispettive variabili
    d'ambiente sono configurate.
    """
    providers: list[ReputationProvider] = [UrlhausProvider()]

    # MISP — richiede MISP_URL + MISP_API_KEY
    if os.environ.get("MISP_URL") and os.environ.get("MISP_API_KEY"):
        from graph_engine.osint.reputation.misp import MispProvider

        providers.append(MispProvider())

    # OpenCTI — richiede OPENCTI_URL + OPENCTI_API_KEY
    if os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_API_KEY"):
        from graph_engine.osint.reputation.opencti import OpenCtiProvider

        providers.append(OpenCtiProvider())

    return providers
