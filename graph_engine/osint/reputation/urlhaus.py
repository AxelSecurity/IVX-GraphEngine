"""URLhaus provider — API pubblica, nessuna chiave richiesta.

URLhaus (https://urlhaus.abuse.ch) è un progetto di abuse.ch che
aggrega URL malevole da fonti multiple. L'API è gratuita e non
richiede autenticazione.
"""

from __future__ import annotations

import httpx

from graph_engine.osint.cache import TTL_URLHAUS, cache_get, cache_set
from graph_engine.osint.reputation.base import ReputationProvider

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_TIMEOUT = 10.0


class UrlhausProvider(ReputationProvider):
    """Verifica un URL contro il feed URLhaus di abuse.ch."""

    def __init__(self) -> None:
        self._provider = "urlhaus"

    async def check(self, url: str, client: httpx.AsyncClient) -> dict:
        """Interroga URLhaus per *url*."""
        cached = cache_get("urlhaus", url, TTL_URLHAUS)
        if cached is not None:
            return cached

        result = await self._query(url, client)
        cache_set("urlhaus", url, result)
        return result

    async def _query(self, url: str, client: httpx.AsyncClient) -> dict:
        try:
            response = await client.post(
                URLHAUS_API_URL,
                data={"url": url},
                timeout=URLHAUS_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.TimeoutException:
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": f"URLhaus timeout after {URLHAUS_TIMEOUT}s"},
            }
        except Exception as exc:
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": f"URLhaus query failed: {exc}"},
            }

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"query_status": "no_results"},
            }

        # URL presente nel feed
        return {
            "provider": self._provider,
            "listed": True,
            "details": data,
        }
