"""OpenCTI adapter — predisposto ma disabilitato di default.

Si attiva solo se le variabili d'ambiente ``OPENCTI_URL`` e
``OPENCTI_API_KEY`` sono entrambe configurate. Altrimenti
``check()`` restituisce immediatamente ``listed=False``
senza tentare alcuna chiamata HTTP.
"""

from __future__ import annotations

import os

import httpx

from graph_engine.osint.reputation.base import ReputationProvider

OPENCTI_TIMEOUT = 15.0


def _is_configured() -> bool:
    """True se entrambe le variabili d'ambiente OpenCTI sono presenti."""
    return bool(
        os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_API_KEY")
    )


class OpenCtiProvider(ReputationProvider):
    """Provider OpenCTI per ricerca IOC via GraphQL API."""

    def __init__(self) -> None:
        self._provider = "opencti"
        self._base_url = os.environ.get("OPENCTI_URL", "")
        self._api_key = os.environ.get("OPENCTI_API_KEY", "")

    async def check(self, url: str, client: httpx.AsyncClient) -> dict:
        """Cerca *url* in OpenCTI. Se non configurato, restituisce skipped."""
        if not _is_configured():
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"skipped": "not configured"},
            }

        return await self._search(url, client)

    async def _search(self, url: str, client: httpx.AsyncClient) -> dict:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        query = """
        query SearchIndicator($search: String) {
          indicators(search: $search) {
            edges {
              node {
                id
                name
                pattern_type
                created
              }
            }
          }
        }
        """

        try:
            response = await client.post(
                f"{self._base_url.rstrip('/')}/graphql",
                headers=headers,
                json={
                    "query": query,
                    "variables": {"search": url},
                },
                timeout=OPENCTI_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": str(exc)},
            }

        edges = (
            data.get("data", {})
            .get("indicators", {})
            .get("edges", [])
        )
        listed = len(edges) > 0

        return {
            "provider": self._provider,
            "listed": listed,
            "details": {
                "match_count": len(edges),
            },
        }
