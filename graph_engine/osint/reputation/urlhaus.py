"""URLhaus provider — predisposto ma disabilitato senza Auth-Key.

URLhaus (https://urlhaus.abuse.ch) è un progetto di abuse.ch che
aggrega URL malevole da fonti multiple.  L'API richiede ora una
Auth-Key gratuita (https://auth.abuse.ch/) inviata nell'header
``Auth-Key``: senza la variabile ``URLHAUS_API_KEY`` il provider
resta disabilitato e ``check()`` restituisce immediatamente
``listed=False`` senza tentare alcuna chiamata HTTP.
"""

from __future__ import annotations

import httpx

from graph_engine.config import settings
from graph_engine.osint.cache import TTL_URLHAUS, cache_get, cache_set
from graph_engine.osint.reputation.base import ReputationProvider

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_TIMEOUT = 10.0


def _is_configured() -> bool:
    """True se la Auth-Key URLhaus è presente (vedi config)."""
    return settings.urlhaus_configured


class UrlhausProvider(ReputationProvider):
    """Verifica un URL contro il feed URLhaus di abuse.ch."""

    def __init__(self) -> None:
        self._provider = "urlhaus"
        self._api_key = settings.urlhaus_api_key or ""

    async def check(self, url: str, client: httpx.AsyncClient) -> dict:
        """Interroga URLhaus per *url*. Se non configurato, skipped."""
        if not _is_configured():
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"skipped": "not configured"},
            }

        cached = cache_get("urlhaus", url, TTL_URLHAUS)
        if cached is not None:
            return cached

        result = await self._query(url, client)
        cache_set("urlhaus", url, result)
        return result

    async def _query(self, url: str, client: httpx.AsyncClient) -> dict:
        headers = {"Auth-Key": self._api_key} if self._api_key else {}
        try:
            response = await client.post(
                URLHAUS_API_URL,
                headers=headers,
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
        except httpx.HTTPStatusError as exc:
            # 401 = Auth-Key assente, invalida o scaduta — gestito come
            # provider_unavailable pulito, mai come eccezione che risale.
            if exc.response.status_code == 401:
                return {
                    "provider": self._provider,
                    "listed": False,
                    "details": {
                        "error": (
                            "URLhaus auth failed: HTTP 401 — "
                            "Auth-Key invalida o scaduta"
                        )
                    },
                }
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": f"URLhaus HTTP error: {exc}"},
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
