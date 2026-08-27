"""OpenCTI provider — osservabili STIX con semantica "IOC attivo".

Si attiva solo se le variabili d'ambiente ``OPENCTI_URL`` e
``OPENCTI_API_KEY`` sono entrambe configurate. Altrimenti
``check()`` restituisce immediatamente ``listed=False``
senza tentare alcuna chiamata HTTP.

Forma della query — verificata contro la documentazione ufficiale
(docs.opencti.io) e il sorgente ``OpenCTI-Platform/opencti``
(``opencti-graphql/``, branch master):

- Ricerca per osservabile ESAATTO via ``stixCyberObservables`` con
  filtro ``{ key: ["value"], values: [x], operator: eq }``: il campo
  ``value`` è filtrabile con ``eq`` per Url, Hostname, Domain-Name,
  IPv4-Addr e IPv6-Addr
  (``stixCyberObservable-registrationAttributes.ts``).  Un filtro
  per valore candidato, combinati con ``FilterGroup`` ``mode: or``
  (unico modo verificato per esprimere "uno qualunque di questi
  valori": la semantica multi-valore di un singolo filtro ``eq``
  non è documentata).
- Il search full-text ``search:`` è deliberatamente NON usato per la
  decisione: è una query_string Lucene con wildcard trailing
  implicita (``engine.ts``, ``processSearch``) — un match per
  prefisso (es. ``example.com`` → ``example.com.evil.net``) non è
  un IOC verificato.  ``eq`` è un confronto esatto di campo, senza
  sintassi Lucene e senza escape.
- Contesto relazionale in un'unica query: ``indicators(first:)``
  annidato sull'osservabile risale agli Indicator correlati
  (``revoked``, ``valid_until``, ``x_opencti_score``,
  ``objectLabel``, ``createdBy``).
- Auth: ``Authorization: Bearer <API key>`` + ``Content-Type:
  application/json`` su POST ``/graphql`` (docs/docs/reference/api.md,
  confermato dal client ufficiale ``pycti``, ``opencti_api_client.py``).

Semantica del risultato (IOC-attivo):

- ``listed=True`` SOLO se almeno un osservabile ha almeno un
  Indicator correlato ATTIVO: non ``revoked`` e con ``valid_until``
  non superato.  Un IOC attivo su OpenCTI decide malevolo senza il
  modello (regola del prefilter, come MISP to_ids).
- Osservabile presente ma senza Indicator attivo (nessun indicatore,
  tutti revoked o tutti scaduti) → ``listed=False`` ma
  ``details.context_only=True``: contesto informativo, NON
  equiparabile a un hit (principio del progetto: mai penalizzare
  per segnale debole).
- ``valid_until`` non parsabile → l'indicatore NON è considerato
  attivo (conservativo: la decisione deterministica non si basa su
  dati incomprensibili).
- Qualunque errore (rete, timeout, risposta malformata) produce
  ``listed=False`` con ``details.error`` — mai un'eccezione.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import httpx

from graph_engine.config import settings
from graph_engine.osint.reputation._search_values import build_search_values
from graph_engine.osint.reputation.base import ReputationProvider

OPENCTI_TIMEOUT = 15.0

# Tipi STIX osservabili cercati — nomi ESATTI del backend OpenCTI
# (``stixCyberObservable.ts``: ENTITY_URL = 'Url', ENTITY_DOMAIN_NAME =
# 'Domain-Name', ENTITY_IPV4_ADDR = 'IPv4-Addr', ENTITY_IPV6_ADDR =
# 'IPv6-Addr', ENTITY_HOSTNAME = 'Hostname').
_TYPES = ["Url", "Hostname", "Domain-Name", "IPv4-Addr", "IPv6-Addr"]

# Limiti di pagina: default Elasticsearch 500, max 5000 (``engine.ts``).
# 100 per pagina è ampiamente sotto entrambi.
_MAX_OBSERVABLES = 100
_MAX_INDICATORS_PER_OBSERVABLE = 100

# Campi tutti verificati sullo schema ufficiale
# (``indicator.graphql``, ``stixCyberObservable`` interface,
# ``PageInfo``): entity_type, observable_value, x_opencti_score,
# objectMarking.definition, objectLabel.value, createdBy.name,
# e sugli Indicator: revoked, valid_until, x_opencti_detection.
_QUERY = """
query SearchObservables($types: [String], $filters: FilterGroup) {
  stixCyberObservables(first: 100, types: $types, filters: $filters) {
    pageInfo {
      globalCount
    }
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
        objectMarking {
          definition
          definition_type
        }
        objectLabel {
          value
        }
        createdBy {
          name
        }
        indicators(first: 100) {
          edges {
            node {
              id
              name
              pattern_type
              revoked
              valid_until
              x_opencti_score
              x_opencti_detection
              createdBy {
                name
              }
              objectLabel {
                value
              }
            }
          }
        }
      }
    }
  }
}
"""


def _is_configured() -> bool:
    """True se entrambe le variabili OpenCTI sono presenti (vedi config)."""
    return settings.opencti_configured


def _parse_valid_until(value) -> Optional[datetime]:
    """Parsa ``valid_until`` (DateTime ISO-8601) o None se vuoto/illeggibile.

    I DateTime OpenCTI sono UTC.  Python 3.9: ``fromisoformat`` non
    accetta il suffisso ``Z`` — sostituito con ``+00:00``.  Le stringhe
    naive vengono trattate come UTC.  None significa "assente O non
    parsabile": la distinzione (che cambia la semantica) spetta al
    chiamante ``_is_active_indicator``.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _is_active_indicator(node: dict, now: datetime) -> bool:
    """True se l'Indicator non è revoked e non è scaduto.

    Conservativo per la decisione deterministica "malevolo certo":
    un ``valid_until`` PRESENTE ma non parsabile rende l'indicatore
    NON attivo — meglio delegare che decidere su dati incomprensibili.
    Un ``valid_until`` assente (None) è invece una scadenza mai
    impostata: nessun vincolo temporale.
    """
    if node.get("revoked"):
        return False
    valid_until = node.get("valid_until")
    if valid_until:
        parsed = _parse_valid_until(valid_until)
        if parsed is None:
            return False
        if now > parsed:
            return False
    return True


def _collect_node_context(
    node: dict,
    labels: set[str],
    markings: set[str],
    created_by: set[str],
) -> None:
    """Raccoglie label/marking/organizzazione da un nodo (observable o
    indicator) nei set condivisi — mai il payload grezzo."""
    for lbl in node.get("objectLabel") or []:
        if isinstance(lbl, dict) and lbl.get("value"):
            labels.add(str(lbl["value"]))
    for marking in node.get("objectMarking") or []:
        if isinstance(marking, dict) and marking.get("definition"):
            markings.add(str(marking["definition"]))
    creator = (node.get("createdBy") or {}).get("name")
    if creator:
        created_by.add(str(creator))


class OpenCtiProvider(ReputationProvider):
    """Provider OpenCTI per ricerca IOC via GraphQL API."""

    def __init__(self) -> None:
        self._provider = "opencti"
        self._base_url = settings.opencti_url or ""
        self._api_key = settings.opencti_api_key or ""

    async def check(
        self,
        url: str,
        client: httpx.AsyncClient,
        timeout_s: Optional[float] = None,
        known_ips: Optional[list[str]] = None,
    ) -> dict:
        """Cerca *url* in OpenCTI. Se non configurato, restituisce skipped.

        ``known_ips`` (record A/AAAA risolti da L2) vengono inclusi
        nella query come filtri ``value`` eq — un solo round-trip
        GraphQL copre URL, hostname, dominio e IP.
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
        values = build_search_values(url, known_ips)
        if not values:
            return {
                "provider": self._provider,
                "listed": False,
                "details": {"error": "no candidate search values"},
            }

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        # Un filtro ``eq`` per valore candidato, OR a livello di gruppo:
        # "uno qualunque di questi valori, confronto esatto".
        filters = {
            "mode": "or",
            "filters": [
                {"key": ["value"], "values": [v], "operator": "eq"}
                for v in values
            ],
            "filterGroups": [],
        }

        try:
            response = await client.post(
                f"{self._base_url.rstrip('/')}/graphql",
                headers=headers,
                json={
                    "query": _QUERY,
                    "variables": {"types": _TYPES, "filters": filters},
                },
                timeout=timeout_s if timeout_s is not None else OPENCTI_TIMEOUT,
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
            .get("stixCyberObservables", {})
            .get("edges", [])
        )
        if not isinstance(edges, list):
            return {
                "provider": self._provider,
                "listed": False,
                "details": {
                    "error": "malformed OpenCTI response: edges is not a list"
                },
            }
        return self._summarise(edges)

    def _summarise(self, edges: list) -> dict:
        """Estrae da *edges* un riepilogo compatto e IOC-attivo-aware.

        Mai il payload grezzo: solo conteggi, tipi osservati, label,
        marking (TLP), organizzazioni e lo score degli indicatori
        attivi.  ``listed`` è True solo con almeno un Indicator attivo.
        """
        now = datetime.now(timezone.utc)
        matched_types: set[str] = set()
        labels: set[str] = set()
        markings: set[str] = set()
        created_by: set[str] = set()
        observable_count = 0
        total_indicators = 0
        active_indicators = 0
        active_scores: list[float] = []

        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            if not isinstance(node, dict):
                continue
            observable_count += 1

            entity_type = node.get("entity_type")
            if entity_type:
                matched_types.add(str(entity_type))
            _collect_node_context(node, labels, markings, created_by)

            ind_edges = (node.get("indicators") or {}).get("edges", [])
            if not isinstance(ind_edges, list):
                ind_edges = []
            for ind_edge in ind_edges:
                ind = (
                    ind_edge.get("node")
                    if isinstance(ind_edge, dict)
                    else None
                )
                if not isinstance(ind, dict):
                    continue
                total_indicators += 1
                if _is_active_indicator(ind, now):
                    active_indicators += 1
                    score = ind.get("x_opencti_score")
                    if isinstance(score, (int, float)):
                        active_scores.append(float(score))
                _collect_node_context(ind, labels, markings, created_by)

        active_ioc = active_indicators > 0
        context_only = observable_count > 0 and not active_ioc

        return {
            "provider": self._provider,
            "listed": active_ioc,
            "details": {
                "match_count": observable_count,
                "matched_types": sorted(matched_types),
                "active_indicator_count": active_indicators,
                "total_indicator_count": total_indicators,
                "labels": sorted(labels),
                "markings": sorted(markings),
                "created_by": sorted(created_by),
                "score_min": min(active_scores) if active_scores else None,
                "score_max": max(active_scores) if active_scores else None,
                "score_avg": (
                    round(sum(active_scores) / len(active_scores), 1)
                    if active_scores
                    else None
                ),
                "active_ioc_match": active_ioc,
                "context_only": context_only,
            },
        }
