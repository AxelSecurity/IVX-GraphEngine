"""MISP adapter — predisposto ma disabilitato di default.

Si attiva solo se le variabili d'ambiente ``MISP_URL`` e
``MISP_API_KEY`` sono entrambe configurate. Altrimenti
``check()`` restituisce immediatamente ``listed=False``
senza tentare alcuna chiamata HTTP.
"""

from __future__ import annotations

import os

import httpx

from graph_engine.osint.reputation.base import ReputationProvider

MISP_TIMEOUT = 15.0


def _is_configured() -> bool:
    """True se entrambe le variabili d'ambiente MISP sono presenti."""
    return bool(os.environ.get("MISP_URL") and os.environ.get("MISP_API_KEY"))


class MispProvider(ReputationProvider):
    """Provider MISP per ricerca IOC via REST API standard."""

    def __init__(self) -> None:
        self._provider = "misp"
        self._base_url = os.environ.get("MISP_URL", "")
        self._api_key = os.environ.get("MISP_API_KEY", "")

    async def check(self, url: str, client: httpx.AsyncClient) -> dict:
        """Cerca *url* in MISP. Se non configurato, restituisce skipped."""
        if not _is_configured():
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"skipped": "not configured"},
            }

        return await self._search(url, client)

    async def _search(self, url: str, client: httpx.AsyncClient) -> dict:
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
        }

        try:
            response = await client.post(
                f"{self._base_url.rstrip('/')}/attributes/restSearch",
                headers=headers,
                json={
                    "value": url,
                    "type": "url",
                },
                timeout=MISP_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": str(exc)},
            }

        attributes = data.get("response", {}).get("Attribute", [])
        listed = len(attributes) > 0

        return {
            "provider": self._provider,
            "listed": listed,
            "details": {
                "match_count": len(attributes),
            },
        }
