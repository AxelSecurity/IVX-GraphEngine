"""Orchestratore L2 — analisi passiva / OSINT.

Sequenza: DNS PRIMA (gli IP risolti alimentano i reputation
provider, es. MISP cerca anche per ``ip-dst``), poi ctlogs.dev,
RDAP e tutti i provider di reputazione abilitati IN PARALLELO.  Un
fallimento su una fonte non blocca mai le altre (``asyncio.gather``
con ``return_exceptions=True``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from graph_engine.osint.certificate_transparency import query_ctlogs
from graph_engine.osint.dns_resolve import resolve_dns
from graph_engine.osint.rdap import query_rdap
from graph_engine.osint.reputation.registry import get_enabled_providers

# ---------------------------------------------------------------------------
# Pesi per il passive_risk_score
# ---------------------------------------------------------------------------
# Lo score aggregato È la somma dei ``weight`` delle Evidence prodotte
# (single source of truth: non esiste un accumulo parallelo di risk).
# Ogni segnale contribuente porta weight>0 sulla propria Evidence; le
# evidenze informative (provider_unavailable, dns_*) hanno weight=0.0
# e non pesano.  La somma è clampata a [0, 1].
# Ogni peso è documentato con la propria semantica.
# Principio: MAI penalizzare per l'assenza di segnale, solo per la presenza.

_W_DOMAIN_AGE_YOUNG = 0.35     # dominio registrato da < 30 giorni
_W_DOMAIN_AGE_MODERATE = 0.15  # dominio registrato da 30-90 giorni
_W_SIBLING_DOMAINS = 0.30      # presenza di domini fratelli (stessa campagna)
_W_FRESH_CERT = 0.15           # cert più recente emesso da < 30 giorni nel
                               # fallback ctlogs senza SAN (infrastruttura
                               # appena messa in piedi — indizio debole)
_W_REPUTATION_HIT = 0.50       # URL presente in un feed di minacce (peso alto)
_W_MISP_IDS_HIT = 0.55         # hit MISP con to_ids=true — feed curato
                               # manualmente dagli analisti, vale
                               # leggermente più di un feed automatizzato
_W_OPENCTI_ACTIVE_HIT = 0.55   # IOC attivo su OpenCTI (non revoked, non
                               # scaduto) — stessa decisione deterministica
                               # del MISP to_ids: segnale malevolo verificato

# Soglie età dominio
_AGE_YOUNG_DAYS = 30     # sotto questa soglia → young (molto sospetto)
_AGE_MODERATE_DAYS = 90   # sotto questa soglia → moderate (sospetto)

# Timeout globale per il client HTTP condiviso
_HTTPX_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evidence(
    key: str,
    value: Any,
    weight: float,
) -> dict:
    """Costruisce un dizionario evidenza L2 pronto per ``Evidence(**kw)``."""
    return {
        "scope": "target",
        "layer": "L2",
        "key": key,
        "value": value,
        "weight": weight,
        "produced_by": "osint",
        "ts": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Orchestratore principale
# ---------------------------------------------------------------------------


async def analyze(
    canonical_url: str,
    timeout_s: float | None = None,
) -> dict:
    """Esegue tutte le query OSINT L2 su *canonical_url*.

    La risoluzione DNS avviene PRIMA; ctlogs.dev, RDAP e i reputation
    provider partono POI in parallelo.  La sequenza non è più
    interamente parallela perché gli IP risolti alimentano i provider
    (MISP cerca anche per ``ip-dst``): senza di essi una query MISP
    coprirebbe solo URL/dominio e perderebbe i match per IP.  Il costo
    è un round-trip DNS sul cammino critico; il guadagno è il valore
    informativo della query MISP.  Se una fonte fallisce, le altre
    continuano — ``return_exceptions=True`` su ``asyncio.gather``.

    Args:
        canonical_url: URL normalizzato (output di L0 canonicalize).
        timeout_s: Timeout HTTP in secondi per ctlogs.dev, RDAP, DNS e
                   i reputation provider (MISP/OpenCTI/URLhaus).  Se
                   ``None``, ogni fonte usa il proprio default
                   (15s, 15s, 5s, 15s, 15s, 10s rispettivamente).

    Returns:
        dict con chiavi:
        - ``evidence``: list[dict] — una entry per segnale reale trovato
        - ``passive_risk_score``: float — punteggio grezzo 0-1
    """
    parsed = urlparse(canonical_url)
    hostname = parsed.hostname or ""

    if not hostname:
        return {"evidence": [], "passive_risk_score": 0.0}

    evidence: list[dict] = []

    # Client HTTP condiviso: il ceiling segue timeout_s, così nel fast
    # path (timeout_s=5.0) ogni richiesta è cappata a 5s invece dei 30s
    # di default (i provider hanno anche il proprio timeout
    # per-chiamata, ugualmente parametrizzato).
    async with httpx.AsyncClient(
        timeout=timeout_s if timeout_s is not None else _HTTPX_TIMEOUT
    ) as client:
        providers = get_enabled_providers()

        # ── DNS PRIMA — poi il resto in parallelo ────────────────────────
        # Questa parte NON è più interamente parallela, per scelta:
        # gli IP risolti devono raggiungere i reputation provider
        # (MISP include gli ``ip-dst`` nella query restSearch).  Una
        # query MISP senza IP coprirebbe solo URL/hostname/dominio e
        # perderebbe i match su infrastruttura condivisa.  Il costo è
        # un round-trip DNS sul cammino critico (cache 1h mitiga).
        # resolve_dns non rilancia MAI: gli errori diventano ``error``
        # popolato (vedi dns_resolve.py).
        dns_result = await resolve_dns(hostname, timeout=timeout_s)

        known_ips: list[str] = []
        if isinstance(dns_result, dict) and not dns_result.get("error"):
            raw_ips = (
                dns_result.get("a_records", [])
                + dns_result.get("aaaa_records", [])
            )
            # Solo gli indirizzi validi: stringhe non vuote (i resolver
            # possono sporcare le liste con None o stringhe bianche).
            known_ips = [
                ip for ip in raw_ips
                if isinstance(ip, str) and ip.strip()
            ]

        # ── ctlogs.dev + RDAP + reputation provider IN PARALLELO ────────
        ctlogs_task = query_ctlogs(hostname, client, timeout=timeout_s)
        rdap_task = query_rdap(hostname, client, timeout=timeout_s)
        rep_tasks = [
            p.check(
                canonical_url,
                client,
                timeout_s=timeout_s,
                known_ips=known_ips,
            )
            for p in providers
        ]

        results = await _gather_ignore_exceptions(
            ctlogs_task, rdap_task, *rep_tasks
        )

        ctlogs_result = results[0]
        rdap_result = results[1]
        rep_results = results[2:]

        # ── ctlogs.dev: domini fratelli / cronologia certificati ───────
        if not isinstance(ctlogs_result, dict) or "error" in ctlogs_result:
            # Eccezione catturata dal gather o error del provider →
            # evidenza informativa, l'analisi continua.
            reason = (
                ctlogs_result["error"]
                if isinstance(ctlogs_result, dict)
                else str(ctlogs_result)
            )
            evidence.append(_make_evidence(
                key="provider_unavailable",
                value={"provider": "ctlogs.dev", "reason": reason},
                weight=0.0,
            ))
        else:
            siblings = ctlogs_result.get("sibling_domains", [])
            if siblings:
                evidence.append(_make_evidence(
                    key="sibling_domains",
                    value={
                        "domains": siblings,
                        "truncated": ctlogs_result.get("truncated", False),
                        "total_siblings": ctlogs_result.get("total_siblings", len(siblings)),
                        "newest_cert_days": ctlogs_result.get("newest_cert_days"),
                        "oldest_cert_days": ctlogs_result.get("oldest_cert_days"),
                        "total_certs": ctlogs_result.get("total_certs"),
                        "source": ctlogs_result.get("source", "ctlogs.dev"),
                    },
                    weight=_W_SIBLING_DOMAINS,
                ))
            else:
                # Niente sibling (modalità anonima, o dominio senza SAN
                # condivisi): resta la cronologia certificati.  Un cert
                # emesso da < 30 giorni è un indizio debole di
                # infrastruttura appena messa in piedi; altrimenti solo
                # informativa (mai penalizzare per assenza di segnale).
                newest = ctlogs_result.get("newest_cert_days")
                if newest is not None:
                    weight = _W_FRESH_CERT if newest <= 30 else 0.0
                    evidence.append(_make_evidence(
                        key="certificate_history",
                        value={
                            "newest_cert_days": newest,
                            "oldest_cert_days": ctlogs_result.get("oldest_cert_days"),
                            "total_certs": ctlogs_result.get("total_certs"),
                            "source": "ctlogs.dev",
                            "mode": ctlogs_result.get("mode"),
                        },
                        weight=weight,
                    ))

        # ── RDAP: età dominio, registrar, nameserver ──────────────────
        if isinstance(rdap_result, dict):
            if "error" in rdap_result:
                evidence.append(_make_evidence(
                    key="provider_unavailable",
                    value={"provider": "rdap", "reason": rdap_result["error"]},
                    weight=0.0,
                ))
            else:
                age_days = rdap_result.get("domain_age_days")
                if age_days is not None:
                    if age_days < _AGE_YOUNG_DAYS:
                        evidence.append(_make_evidence(
                            key="domain_age_days",
                            value={
                                "age_days": age_days,
                                "category": "young",
                                "registrar": rdap_result.get("registrar"),
                                "nameservers": rdap_result.get("nameservers", []),
                            },
                            weight=_W_DOMAIN_AGE_YOUNG,
                        ))
                    elif age_days < _AGE_MODERATE_DAYS:
                        evidence.append(_make_evidence(
                            key="domain_age_days",
                            value={
                                "age_days": age_days,
                                "category": "moderate",
                                "registrar": rdap_result.get("registrar"),
                                "nameservers": rdap_result.get("nameservers", []),
                            },
                            weight=_W_DOMAIN_AGE_MODERATE,
                        ))
                    # Dominio > 90 giorni: nessuna penalizzazione
                    # (MAI penalizzare per l'assenza di segnale)
        else:
            # Eccezione catturata da asyncio.gather
            evidence.append(_make_evidence(
                key="provider_unavailable",
                value={"provider": "rdap", "reason": str(rdap_result)},
                weight=0.0,
            ))

        # ── DNS: record A e AAAA ─────────────────────────────────────
        if isinstance(dns_result, dict):
            if dns_result.get("error"):
                evidence.append(_make_evidence(
                    key="provider_unavailable",
                    value={"provider": "dns", "reason": dns_result["error"]},
                    weight=0.0,
                ))
            else:
                a_records = dns_result.get("a_records", [])
                aaaa_records = dns_result.get("aaaa_records", [])
                if a_records:
                    evidence.append(_make_evidence(
                        key="dns_a_records",
                        value={"addresses": a_records},
                        weight=0.0,
                    ))
                if aaaa_records:
                    evidence.append(_make_evidence(
                        key="dns_aaaa_records",
                        value={"addresses": aaaa_records},
                        weight=0.0,
                    ))
                # MAI evidenza per l'assenza di record — coerente con il
                # principio del progetto
        else:
            # Eccezione catturata da asyncio.gather
            evidence.append(_make_evidence(
                key="provider_unavailable",
                value={"provider": "dns", "reason": str(dns_result)},
                weight=0.0,
            ))

        # ── Reputation providers ───────────────────────────────────────
        for i, rep_result in enumerate(rep_results):
            if not isinstance(rep_result, dict):
                # Eccezione catturata da _gather_ignore_exceptions
                evidence.append(_make_evidence(
                    key="provider_unavailable",
                    value={
                        "provider": (
                            providers[i]._provider if i < len(providers)
                            else "unknown"
                        ),
                        "reason": str(rep_result),
                    },
                    weight=0.0,
                ))
                continue

            provider_name = rep_result.get("provider", "unknown")

            if "error" in rep_result.get("details", {}):
                evidence.append(_make_evidence(
                    key="provider_unavailable",
                    value={
                        "provider": provider_name,
                        "reason": rep_result["details"]["error"],
                    },
                    weight=0.0,
                ))
            elif rep_result.get("details", {}).get("skipped"):
                # Provider disabilitato — nessuna evidenza, è volontario
                pass
            elif rep_result.get("listed"):
                details = rep_result["details"]
                # Gli hit "verificati" valgono più di un feed
                # automatizzato (URLhaus): MISP to_ids=true (feed curato
                # manualmente per gli IDS) e IOC attivo su OpenCTI
                # (non revoked, non scaduto) decidono malevolo anche
                # nel prefilter.
                weight = (
                    _W_MISP_IDS_HIT
                    if details.get("to_ids_match")
                    else _W_OPENCTI_ACTIVE_HIT
                    if details.get("active_ioc_match")
                    else _W_REPUTATION_HIT
                )
                evidence.append(_make_evidence(
                    key="reputation_hit",
                    value=details,
                    weight=weight,
                ))
            elif rep_result.get("details", {}).get("context_only"):
                # Match informativo: MISP con SOLO to_ids=false, oppure
                # osservabile OpenCTI senza Indicator attivo.  Mai
                # penalizzare per segnale debole → weight 0.0, ma
                # l'evidenza resta visibile per il classificatore.
                evidence.append(_make_evidence(
                    key=f"{provider_name}_context_match",
                    value=rep_result["details"],
                    weight=0.0,
                ))
            # else: listed=False, nessun segnale → no evidence (principio:
            # l'assenza di segnale non è un segnale)

    # ── Score aggregato: derivato dai weight (single source of truth) ──
    # passive_risk_score È la somma dei weight delle Evidence prodotte:
    # ogni segnale contribuente porta weight>0 sulla propria Evidence,
    # le evidenze informative hanno weight=0.0.  Nessun accumulo
    # parallelo di risk — un solo posto decide il contributo di ogni
    # segnale.
    risk = sum(ev["weight"] for ev in evidence)

    return {
        "evidence": evidence,
        "passive_risk_score": round(min(1.0, risk), 4),
    }


# ---------------------------------------------------------------------------
# asyncio.gather con return_exceptions + normalizzazione
# ---------------------------------------------------------------------------


async def _gather_ignore_exceptions(*coros):
    """Esegue coroutine in parallelo; le eccezioni diventano valori di ritorno.

    Equivalente a ``asyncio.gather(..., return_exceptions=True)`` ma con
    un nome che ne documenta l'intento: un fallimento su una fonte non
    deve MAI bloccare le altre.
    """
    import asyncio

    return await asyncio.gather(*coros, return_exceptions=True)
