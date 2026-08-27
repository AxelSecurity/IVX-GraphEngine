"""MISP provider — restSearch multi-tipo con contesto evento.

Si attiva solo se le variabili d'ambiente ``MISP_URL`` e
``MISP_API_KEY`` sono entrambe configurate. Altrimenti
``check()`` restituisce immediatamente ``listed=False``
senza tentare alcuna chiamata HTTP.

Forma della query — verificata contro la documentazione ufficiale
MISP (OpenAPI ``/attributes/restSearch``, misp-book "Automation API"
e sorgente 2.4 ``Attribute.php``/``Event.php``/``AppModel.php``):

- ``value`` accetta una LISTA di stringhe nel body JSON: lato server
  ``convert_filters()`` la trasforma in ``OR … IN`` su
  ``Attribute.value1``/``Attribute.value2``. Anche ``type`` accetta
  una lista (stessa ``convert_filters``).
- ``includeContext: 1`` annida in OGNI attributo della risposta
  l'oggetto ``Event`` completo (``info``, ``threat_level_id``,
  ``Tag``, ``Orgc``) — necessario per estrarre tag e metadati
  dell'evento, non solo l'attributo nudo.
- I valori candidati della query vengono da
  ``_search_values.build_search_values`` (modulo condiviso con gli
  altri provider: URL, hostname, dominio registrabile, IP noti).

Semantica del risultato (to_ids-aware):

- ``listed=True`` SOLO se esiste almeno un match con ``to_ids=true``
  (IOC destinato agli IDS, curato manualmente dagli analisti).
- Match SOLO con ``to_ids=false`` → ``listed=False`` ma
  ``details.context_only=True``: contesto informativo, NON
  equiparabile a un hit (principio del progetto: mai penalizzare
  per segnale debole).
- Qualunque errore (rete, timeout, risposta malformata) produce
  ``listed=False`` con ``details.error`` — mai un'eccezione.
"""

from __future__ import annotations

from typing import Optional

import httpx

from graph_engine.config import settings
from graph_engine.osint.reputation._search_values import build_search_values
from graph_engine.osint.reputation.base import ReputationProvider

MISP_TIMEOUT = 15.0

# Tipi di attributo cercati con l'unica query multi-tipo: coprono
# URL completo, hostname, dominio registrabile e IP di destinazione.
_MISP_TYPES = ["domain", "hostname", "url", "ip-dst"]


def _is_configured() -> bool:
    """True se entrambe le variabili MISP sono presenti (vedi config)."""
    return settings.misp_configured


def _is_to_ids(value) -> bool:
    """Normalizza il flag ``to_ids`` MISP (bool JSON o int 0/1)."""
    return value in (True, 1, "1")


class MispProvider(ReputationProvider):
    """Provider MISP per ricerca IOC via REST API standard."""

    def __init__(self) -> None:
        self._provider = "misp"
        self._base_url = settings.misp_url or ""
        self._api_key = settings.misp_api_key or ""

    async def check(
        self,
        url: str,
        client: httpx.AsyncClient,
        timeout_s: Optional[float] = None,
        known_ips: Optional[list[str]] = None,
    ) -> dict:
        """Cerca *url* in MISP. Se non configurato, restituisce skipped.

        ``known_ips`` (record A/AAAA risolti da L2) vengono inclusi
        nella query come valori ``ip-dst`` — un solo round-trip HTTP
        copre URL, hostname, dominio e IP.
        """
        if not _is_configured():
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"skipped": "not configured"},
            }

        return await self._search(url, client, timeout_s, known_ips)

    async def _search(
        self,
        url: str,
        client: httpx.AsyncClient,
        timeout_s: Optional[float] = None,
        known_ips: Optional[list[str]] = None,
    ) -> dict:
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
        }

        values = build_search_values(url, known_ips)

        try:
            response = await client.post(
                f"{self._base_url.rstrip('/')}/attributes/restSearch",
                headers=headers,
                json={
                    "returnFormat": "json",
                    "value": values,
                    "type": _MISP_TYPES,
                    "includeContext": 1,
                },
                timeout=timeout_s if timeout_s is not None else MISP_TIMEOUT,
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
        if isinstance(attributes, dict):
            # Con un solo match alcuni server MISP serializzano un
            # oggetto singolo invece di una lista — normalizza.
            attributes = [attributes]
        if not isinstance(attributes, list):
            return {
                "provider": self._provider,
                "listed": False,
                "details": {
                    "error": "malformed MISP response: Attribute is not a list"
                },
            }
        return self._summarise(attributes)

    def _summarise(self, attributes: list[dict]) -> dict:
        """Estrae da *attributes* un riepilogo compatto e to_ids-aware.

        Mai il payload grezzo: solo conteggi, tipi, tag deduplicati
        (dall'attributo E dall'evento annidato via ``includeContext``)
        e il flag ``to_ids_match``.
        """
        matched_types: set[str] = set()
        tags: set[str] = set()
        event_ids: set[object] = set()
        to_ids_match = False

        for attr in attributes:
            if not isinstance(attr, dict):
                continue
            attr_type = attr.get("type")
            if attr_type:
                matched_types.add(str(attr_type))
            event_id = attr.get("event_id")
            if event_id is not None:
                event_ids.add(event_id)
            if _is_to_ids(attr.get("to_ids")):
                to_ids_match = True

            # Tag dell'attributo
            for tag in attr.get("Tag") or []:
                name = (tag or {}).get("name")
                if name:
                    tags.add(str(name))
            # Tag dell'evento annidato (presente solo con includeContext)
            event = attr.get("Event") or {}
            for tag in event.get("Tag") or []:
                name = (tag or {}).get("name")
                if name:
                    tags.add(str(name))

        match_count = len(attributes)
        context_only = match_count > 0 and not to_ids_match

        return {
            "provider": self._provider,
            "listed": to_ids_match,
            "details": {
                "match_count": match_count,
                "matched_types": sorted(matched_types),
                "tags": sorted(tags),
                "event_count": len(event_ids),
                "to_ids_match": to_ids_match,
                "context_only": context_only,
            },
        }
