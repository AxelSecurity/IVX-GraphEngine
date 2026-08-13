"""Orchestratore L2 — analisi passiva / OSINT.

Coordina crt.sh, RDAP, e tutti i provider di reputazione abilitati
IN PARALLELO. Un fallimento su una fonte non blocca mai le altre
(``asyncio.gather`` con ``return_exceptions=True``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from graph_engine.osint.certificate_transparency import query_crtsh
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
_W_REPUTATION_HIT = 0.50       # URL presente in un feed di minacce (peso alto)

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

    Le fonti vengono interrogate IN PARALLELO. Se una fallisce, le altre
    continuano — ``return_exceptions=True`` su ``asyncio.gather``.

    Args:
        canonical_url: URL normalizzato (output di L0 canonicalize).
        timeout_s: Timeout HTTP in secondi per crt.sh, RDAP e DNS.
                   Se ``None``, ogni provider usa il proprio default
                   (15s, 15s, 5s rispettivamente).

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

    # Client HTTP condiviso con timeout
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT) as client:
        # ── Lancio parallelo di TUTTE le fonti ──────────────────────────
        providers = get_enabled_providers()

        crtsh_task = query_crtsh(hostname, client, timeout=timeout_s)
        rdap_task = query_rdap(hostname, client, timeout=timeout_s)
        dns_task = resolve_dns(hostname, timeout=timeout_s)
        rep_tasks = [p.check(canonical_url, client) for p in providers]

        all_tasks = [crtsh_task, rdap_task, dns_task] + rep_tasks
        results = await _gather_ignore_exceptions(*all_tasks)

        crtsh_result = results[0]
        rdap_result = results[1]
        dns_result = results[2]
        rep_results = results[3:]

        # ── crt.sh: domini fratelli ────────────────────────────────────
        if isinstance(crtsh_result, dict):
            if "error" in crtsh_result:
                evidence.append(_make_evidence(
                    key="provider_unavailable",
                    value={"provider": "crtsh", "reason": crtsh_result["error"]},
                    weight=0.0,
                ))
            else:
                siblings = crtsh_result.get("sibling_domains", [])
                if siblings:
                    evidence.append(_make_evidence(
                        key="sibling_domains",
                        value={
                            "domains": siblings,
                            "truncated": crtsh_result.get("truncated", False),
                            "total_siblings": crtsh_result.get("total_siblings", len(siblings)),
                            "newest_cert_days": crtsh_result.get("newest_cert_days"),
                            "oldest_cert_days": crtsh_result.get("oldest_cert_days"),
                            "total_certs": crtsh_result.get("total_certs"),
                        },
                        weight=_W_SIBLING_DOMAINS,
                    ))
        else:
            # Eccezione catturata da asyncio.gather
            evidence.append(_make_evidence(
                key="provider_unavailable",
                value={"provider": "crtsh", "reason": str(crtsh_result)},
                weight=0.0,
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
                evidence.append(_make_evidence(
                    key="reputation_hit",
                    value=rep_result["details"],
                    weight=_W_REPUTATION_HIT,
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
