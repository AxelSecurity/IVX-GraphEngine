"""Interfaccia comune per i provider di reputazione.

Tutti i provider devono implementare ``ReputationProvider.check()``
che restituisce un dizionario con almeno:
- ``provider``: nome del provider (str)
- ``listed``: True se l'URL è nella blacklist del provider (bool)
- ``details``: informazioni aggiuntive (dict)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

import httpx


class ReputationProvider(ABC):
    """Classe base astratta per un provider di reputazione."""

    @abstractmethod
    async def check(
        self,
        url: str,
        client: httpx.AsyncClient,
        timeout_s: Optional[float] = None,
    ) -> dict:
        """Verifica la reputazione di *url* presso il provider.

        Args:
            url: L'URL completo da verificare.
            client: Client HTTP asincrono già configurato.
            timeout_s: Timeout HTTP in secondi per la chiamata del
                       provider.  Se ``None``, il provider usa il proprio
                       default (es. ``URLHAUS_TIMEOUT``).

        Returns:
            Un dizionario con almeno:
            - ``provider`` (str): nome del provider
            - ``listed`` (bool): True se l'URL è malevolo noto
            - ``details`` (dict): dettagli aggiuntivi
        """
        ...
