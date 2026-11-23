"""Esportazione su OpenCTI di un'analisi con verdetto malevolo.

Azione manuale dalla dashboard: crea su OpenCTI un **Report** con gli
indicatori dell'analisi.  Il motore NON legge da OpenCTI (le lookup
restano a monte, sul servizio chiamante): qui si scrive soltanto, e solo
su richiesta esplicita di un utente.

Cosa viene creato (API GraphQL di OpenCTI 6.x, via httpx):

- autore (Organization ``OPENCTI_AUTHOR``) e marcatura ``OPENCTI_TLP``
  (default TLP:AMBER), riusati se esistono già;
- label: ``graphengine``, la famiglia (``phishing`` / ``malware-download``)
  e il marchio imitato;
- un Indicator STIX per ogni indicatore scelto — URL analizzato, URL
  finale (se diverso) e dominio — con ``createObservables`` così OpenCTI
  crea anche gli osservabili collegati;
- il Report che li contiene, con la motivazione del verdetto e, se
  ``DASHBOARD_PUBLIC_URL`` è configurato, il link all'analisi.

Il dominio è sempre l'host completo dell'URL (es.
``kit-123.pages.dev``), mai il dominio della piattaforma di hosting
condiviso: altrimenti si bloccherebbe l'intera piattaforma.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from graph_engine.config import settings

logger = logging.getLogger("graph_engine.api.opencti")

_TIMEOUT_S = 30.0


class OpenCtiNotConfigured(Exception):
    """OPENCTI_URL / OPENCTI_API_KEY mancanti."""


class OpenCtiError(Exception):
    """Errore restituito da OpenCTI (HTTP o GraphQL)."""


# ---------------------------------------------------------------------------
# Indicatori
# ---------------------------------------------------------------------------


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_indicators(target) -> list[dict]:
    """Indicatori proposti per l'analisi: URL analizzato, URL finale e
    dominio (host completo) di ciascuno, senza doppioni.

    Ogni voce: ``key`` (stabile, usata dalla dashboard per la selezione),
    ``type`` (``url`` | ``domain``), ``value``, ``pattern`` STIX e
    ``observable_type`` (tipo OpenCTI dell'osservabile principale).
    """
    urls: list[str] = []
    for candidate in (getattr(target, "input_url", None), getattr(target, "final_url", None)):
        if candidate and candidate.startswith(("http://", "https://")) and candidate not in urls:
            urls.append(candidate)

    indicators: list[dict] = []
    seen: set[str] = set()
    for url in urls:
        key = f"url:{url}"
        if key not in seen:
            seen.add(key)
            indicators.append({
                "key": key, "type": "url", "value": url,
                "pattern": f"[url:value = '{_stix_escape(url)}']",
                "observable_type": "Url",
            })
    for url in urls:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        key = f"domain:{host}"
        if host and key not in seen:
            seen.add(key)
            indicators.append({
                "key": key, "type": "domain", "value": host,
                "pattern": f"[domain-name:value = '{_stix_escape(host)}']",
                "observable_type": "Domain-Name",
            })
    return indicators


# ---------------------------------------------------------------------------
# Client GraphQL
# ---------------------------------------------------------------------------


class _OpenCtiClient:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def query(self, query: str, variables: dict[str, Any]) -> dict:
        try:
            response = await self._client.post(
                "/graphql", json={"query": query, "variables": variables},
            )
        except httpx.HTTPError as exc:
            raise OpenCtiError(f"OpenCTI non raggiungibile: {exc}") from exc
        if response.status_code in (401, 403):
            raise OpenCtiError(f"OpenCTI ha rifiutato la chiave API (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise OpenCtiError(f"OpenCTI HTTP {response.status_code}: {response.text[:200]}")
        try:
            body = response.json()
        except ValueError as exc:
            raise OpenCtiError("OpenCTI ha restituito una risposta non JSON") from exc
        if body.get("errors"):
            message = "; ".join(
                str(e.get("message", e)) for e in body["errors"] if isinstance(e, dict)
            ) or str(body["errors"])
            raise OpenCtiError(f"OpenCTI: {message[:300]}")
        return body.get("data") or {}

    async def marking_id(self, definition: str) -> str:
        data = await self.query(
            """query Markings($filters: FilterGroup) {
                 markingDefinitions(filters: $filters, first: 5) {
                   edges { node { id definition } } } }""",
            {"filters": {
                "mode": "and",
                "filters": [{"key": "definition", "values": [definition],
                             "operator": "eq", "mode": "or"}],
                "filterGroups": [],
            }},
        )
        for edge in (data.get("markingDefinitions") or {}).get("edges", []):
            node = edge.get("node") or {}
            if node.get("definition") == definition:
                return node["id"]
        raise OpenCtiError(f"Marcatura {definition!r} non trovata su OpenCTI")

    async def author_id(self, name: str) -> str:
        data = await self.query(
            """mutation Author($input: IdentityAddInput!) {
                 identityAdd(input: $input) { id } }""",
            {"input": {"type": "Organization", "name": name,
                       "description": "Motore di analisi URL GraphEngine"}},
        )
        return data["identityAdd"]["id"]

    async def label_id(self, value: str) -> str:
        data = await self.query(
            """mutation Label($input: LabelAddInput!) {
                 labelAdd(input: $input) { id } }""",
            {"input": {"value": value, "color": "#c62828"}},
        )
        return data["labelAdd"]["id"]

    async def external_reference_id(self, url: str, description: str) -> str:
        data = await self.query(
            """mutation ExtRef($input: ExternalReferenceAddInput!) {
                 externalReferenceAdd(input: $input) { id } }""",
            {"input": {"source_name": settings.opencti_author or "GraphEngine",
                       "url": url, "description": description}},
        )
        return data["externalReferenceAdd"]["id"]

    async def add_indicator(self, indicator: dict, common: dict) -> str:
        data = await self.query(
            """mutation Indicator($input: IndicatorAddInput!) {
                 indicatorAdd(input: $input) { id } }""",
            {"input": {
                "name": indicator["value"],
                "description": common["description"],
                "pattern": indicator["pattern"],
                "pattern_type": "stix",
                "x_opencti_main_observable_type": indicator["observable_type"],
                "createObservables": True,
                "valid_from": common["now"],
                "confidence": common["confidence"],
                "createdBy": common["author"],
                "objectMarking": [common["marking"]],
                "objectLabel": common["labels"],
            }},
        )
        return data["indicatorAdd"]["id"]

    async def indicator_observable_ids(self, indicator_id: str) -> list[str]:
        """Osservabili creati da ``createObservables`` (best-effort)."""
        try:
            data = await self.query(
                """query Obs($id: String!) {
                     indicator(id: $id) { observables { edges { node { id } } } } }""",
                {"id": indicator_id},
            )
        except OpenCtiError:
            return []
        edges = ((data.get("indicator") or {}).get("observables") or {}).get("edges", [])
        return [e["node"]["id"] for e in edges if (e.get("node") or {}).get("id")]

    async def add_report(self, name: str, objects: list[str], common: dict,
                         external_refs: list[str]) -> str:
        data = await self.query(
            """mutation Report($input: ReportAddInput!) {
                 reportAdd(input: $input) { id } }""",
            {"input": {
                "name": name,
                "description": common["description"],
                "published": common["now"],
                "report_types": ["threat-report"],
                "confidence": common["confidence"],
                "createdBy": common["author"],
                "objectMarking": [common["marking"]],
                "objectLabel": common["labels"],
                "objects": objects,
                "externalReferences": external_refs,
            }},
        )
        return data["reportAdd"]["id"]


# ---------------------------------------------------------------------------
# Esportazione
# ---------------------------------------------------------------------------


def _labels_for(verdict) -> list[str]:
    kit = (getattr(verdict, "kit_family", None) or "").lower()
    family = "malware-download" if kit == "malware-download" else "phishing"
    labels = ["graphengine", family]
    brand = (getattr(verdict, "brand", None) or "").strip().lower()
    if brand and brand not in labels:
        labels.append(brand)
    return labels


async def export_analysis(
    data: dict,
    external_response: dict,
    selected_keys: Optional[list[str]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict:
    """Crea il Report OpenCTI per l'analisi *data* e restituisce
    ``{"report_id", "report_url", "indicators"}``.

    Args:
        data: risultato di ``get_target_by_id`` (target, verdict, …).
        external_response: la risposta ``{"result": {...}}`` dell'API
            esterna per l'analisi (nome e motivazione del Report).
        selected_keys: chiavi degli indicatori scelti in dashboard
            (``None`` = tutti quelli proposti).
        transport: trasporto httpx alternativo (test).
    """
    if not settings.opencti_configured:
        raise OpenCtiNotConfigured("OPENCTI_URL e OPENCTI_API_KEY non configurate")

    target = data["target"]
    verdict = data.get("verdict")
    proposed = build_indicators(target)
    if selected_keys is not None:
        wanted = set(selected_keys)
        proposed = [i for i in proposed if i["key"] in wanted]
    if not proposed:
        raise OpenCtiError("Nessun indicatore selezionato")

    result = external_response.get("result", {})
    host = urlparse(target.input_url).hostname or target.input_url
    name = f"{result.get('signature') or 'Phishing'} – {host}"
    description = (
        f"{result.get('reason') or ''}\n\n"
        f"Verdetto GraphEngine: {result.get('verdict')} "
        f"(confidenza {result.get('confidence')}). URL analizzato: "
        f"{target.input_url}. ID analisi: {target.id}."
    ).strip()

    base_url = settings.opencti_url.rstrip("/")
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={"Authorization": f"Bearer {settings.opencti_api_key}"},
        timeout=_TIMEOUT_S,
        transport=transport,
    ) as http:
        cti = _OpenCtiClient(http)
        common = {
            "description": description,
            "now": datetime.now(timezone.utc).isoformat(),
            "confidence": int(round(float(getattr(verdict, "confidence", 0.8) or 0.8) * 100)),
            "marking": await cti.marking_id(settings.opencti_tlp or "TLP:AMBER"),
            "author": await cti.author_id(settings.opencti_author or "GraphEngine"),
            "labels": [await cti.label_id(v) for v in _labels_for(verdict)],
        }
        external_refs: list[str] = []
        if settings.dashboard_public_url:
            link = (
                f"{settings.dashboard_public_url.rstrip('/')}"
                f"/dashboard/#/analyses/{target.id}"
            )
            external_refs.append(
                await cti.external_reference_id(link, "Analisi GraphEngine")
            )

        objects: list[str] = []
        for indicator in proposed:
            indicator_id = await cti.add_indicator(indicator, common)
            objects.append(indicator_id)
            for obs_id in await cti.indicator_observable_ids(indicator_id):
                if obs_id not in objects:
                    objects.append(obs_id)

        report_id = await cti.add_report(name, objects, common, external_refs)

    report_url = f"{base_url}/dashboard/analyses/reports/{report_id}"
    logger.info(
        "Analisi %s esportata su OpenCTI: report %s (%d indicatori)",
        target.id, report_id, len(proposed),
    )
    return {
        "report_id": report_id,
        "report_url": report_url,
        "indicators": [i["value"] for i in proposed],
    }
