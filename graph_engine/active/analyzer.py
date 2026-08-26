"""Orchestratore L3 — analisi attiva low-interaction.

Coordina redirect_chain, favicon, jarm, differential_fetch IN PARALLELO.
Un fallimento su un modulo non blocca mai gli altri
(``asyncio.gather`` con ``return_exceptions=True``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from graph_engine.active.differential_fetch import (
    PROFILES,
    cloaking_probe_profile,
    detect_cloaking,
    differential_fetch,
    recommend_profile,
)
from graph_engine.active.favicon import fetch_favicon_hash
from graph_engine.active.jarm import compute_jarm
from graph_engine.active.redirect_chain import trace_redirect_chain

# ---------------------------------------------------------------------------
# Timeout globale per il client HTTP condiviso
# ---------------------------------------------------------------------------

_HTTPX_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evidence(
    key: str,
    value: Any,
    weight: float = 0.0,
) -> dict:
    """Costruisce un dizionario evidenza L3 pronto per ``Evidence(**kw)``."""
    return {
        "scope": "target",
        "layer": "L3",
        "key": key,
        "value": value,
        "weight": weight,
        "produced_by": "active",
        "ts": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Orchestratore principale
# ---------------------------------------------------------------------------


async def analyze(
    canonical_url: str,
    timeout_s: float | None = None,
) -> dict:
    """Esegue tutte le sonde L3 su *canonical_url* IN PARALLELO.

    Le quattro sonde vengono lanciate simultaneamente. JARM ha bisogno
    solo di hostname/porta, quindi può partire subito insieme alle altre.

    Args:
        canonical_url: URL normalizzato (output di L0 canonicalize).
        timeout_s: Timeout in secondi per JARM. Se ``None``, usa il
                   default (10s). Le altre sonde (redirect_chain,
                   favicon, differential_fetch) mantengono i propri
                   timeout interni.

    Returns:
        dict con chiavi:
        - ``evidence``: list[dict] — evidenze L3 raccolte
        - ``recommended_profile``: dict — profilo raccomandato per L4
          (``user_agent`` + ``headers``)
        - ``cloaking_profile``: dict o None — profilo divergente più ricco
          da esplorare come secondo ramo L4 (``None`` se nessun cloaking)
    """
    parsed = urlparse(canonical_url)
    hostname = parsed.hostname or ""

    evidence: list[dict] = []

    if not hostname:
        return {
            "evidence": evidence,
            "recommended_profile": {
                "user_agent": PROFILES["desktop_chrome"]["user_agent"],
                "headers": dict(PROFILES["desktop_chrome"].get("headers", {})),
            },
            "cloaking_profile": None,
        }

    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT) as client:
        # ── Lancio parallelo di TUTTE le sonde ───────────────────────────
        redirect_task = trace_redirect_chain(canonical_url, client)
        favicon_task = fetch_favicon_hash(canonical_url, client)
        jarm_task = (
            compute_jarm(hostname, timeout_s=timeout_s)
            if timeout_s is not None
            else compute_jarm(hostname)
        )
        diff_task = differential_fetch(canonical_url)

        results = await _gather_ignore_exceptions(
            redirect_task, favicon_task, jarm_task, diff_task,
        )
        redirect_result, favicon_result, jarm_result, diff_result = results

        # ── Redirect chain ──────────────────────────────────────────────
        # trace_redirect_chain NON produce mai una chiave top-level
        # "error": un hop fallito (timeout, connessione rifiutata, DNS)
        # è l'ULTIMO hop della lista, con status_code None e "error"
        # valorizzato. hops vuoto = nessun hop registrato. Il check va
        # fatto sull'ultimo hop, non sul dict intero.
        if isinstance(redirect_result, dict):
            hops = redirect_result.get("hops", [])
            if hops and isinstance(hops[-1], dict):
                last_hop_error = hops[-1].get("error")
            elif not hops:
                last_hop_error = "no hops recorded"
            else:
                last_hop_error = f"malformed hop: {hops[-1]!r}"
        else:
            hops = []
            last_hop_error = str(redirect_result) or "unknown error"

        if last_hop_error:
            evidence.append(_make_evidence(
                key="active_probe_error",
                value={"probe": "redirect_chain", "error": last_hop_error},
                weight=0.0,
            ))
        else:
            hop_count = redirect_result.get("hop_count", 0)
            redirect_count = redirect_result.get("redirect_count", 0)
            evidence.append(_make_evidence(
                key="redirect_hop_count",
                value={
                    "hop_count": hop_count,
                    "redirect_count": redirect_count,
                    "truncated": redirect_result.get("truncated", False),
                    "final_url": redirect_result.get("final_url"),
                },
                weight=0.05 if redirect_count >= 3 else 0.0,
            ))

            # Se ci sono stati >= 3 redirect, è un segnale sospetto
            if redirect_count >= 5:
                evidence.append(_make_evidence(
                    key="excessive_redirects",
                    value={"redirect_count": redirect_count},
                    weight=0.15,
                ))

            # Registra i server header insoliti
            for hop in hops:
                server = hop.get("server")
                if server and _is_unusual_server(server):
                    evidence.append(_make_evidence(
                        key="unusual_server_header",
                        value={"server": server, "hop_url": hop.get("url")},
                        weight=0.05,
                    ))

        # ── Favicon hash ────────────────────────────────────────────────
        if isinstance(favicon_result, dict) and "favicon_hash" in favicon_result:
            evidence.append(_make_evidence(
                key="favicon_hash",
                value={
                    "hash": favicon_result["favicon_hash"],
                    "size_bytes": favicon_result["favicon_size_bytes"],
                },
                weight=0.05,
            ))
        elif favicon_result is not None:
            err_msg = str(favicon_result) if not isinstance(favicon_result, dict) else "unknown"
            evidence.append(_make_evidence(
                key="active_probe_error",
                value={"probe": "favicon", "error": err_msg},
                weight=0.0,
            ))

        # ── JARM ────────────────────────────────────────────────────────
        if isinstance(jarm_result, str) and len(jarm_result) == 62:
            evidence.append(_make_evidence(
                key="jarm_fingerprint",
                value={"hash": jarm_result, "port": 443},
                weight=0.10,
            ))
        elif jarm_result is not None:
            err_msg = str(jarm_result) if not isinstance(jarm_result, str) else "unknown"
            evidence.append(_make_evidence(
                key="active_probe_error",
                value={"probe": "jarm", "error": err_msg},
                weight=0.0,
            ))

        # ── Differential fetch ──────────────────────────────────────────
        recommended_profile: dict = {
            "user_agent": PROFILES["desktop_chrome"]["user_agent"],
            "headers": dict(PROFILES["desktop_chrome"].get("headers", {})),
        }
        cloaking_profile = None

        if isinstance(diff_result, dict) and "results" in diff_result:
            diff_results = diff_result["results"]
            cloaking = detect_cloaking(diff_results)
            recommended_profile = recommend_profile(diff_results, cloaking)
            cloaking_profile = cloaking_probe_profile(diff_results, cloaking)

            if cloaking.get("cloaking_detected"):
                evidence.append(_make_evidence(
                    key="cloaking_detected",
                    value={
                        "divergent_profiles": cloaking.get("divergent_profiles", []),
                        "details": cloaking.get("divergence_details", ""),
                    },
                    weight=0.25,
                ))

            # Aggiungi anche un riepilogo dei profili confrontati
            profiles_summary = {
                name: {
                    "status_code": r.get("status_code"),
                    "content_length": r.get("content_length"),
                }
                for name, r in diff_results.items()
            }
            evidence.append(_make_evidence(
                key="differential_fetch_summary",
                value={
                    "profiles_compared": diff_result.get("profiles_compared", 0),
                    "profiles": profiles_summary,
                },
                weight=0.0,
            ))
        elif diff_result is not None:
            err_msg = str(diff_result) if not isinstance(diff_result, dict) else "unknown"
            evidence.append(_make_evidence(
                key="active_probe_error",
                value={"probe": "differential_fetch", "error": err_msg},
                weight=0.0,
            ))

    return {
        "evidence": evidence,
        "recommended_profile": recommended_profile,
        "cloaking_profile": cloaking_profile,
    }


# ---------------------------------------------------------------------------
# Helpers privati
# ---------------------------------------------------------------------------


async def _gather_ignore_exceptions(*coros):
    """Esegue coroutine in parallelo; le eccezioni diventano valori di ritorno."""
    import asyncio

    return await asyncio.gather(*coros, return_exceptions=True)


def _is_unusual_server(server: str) -> bool:
    """Rileva server header insoliti (es. server embedded, IoT, C2)."""
    unusual_keywords = [
        "Apache-Coyote", "nginx", "Apache", "cloudflare", "CloudFront",
        "Microsoft-IIS", "LiteSpeed", "Caddy", "lighttpd", "Varnish",
        "BigIP", "ATS", "Squid", "HAProxy", "Traefik", "envoy",
    ]
    # I server "normali" non sono insoliti — al contrario, segnaliamo
    # server NON standard che potrebbero indicare infrastruttura atipica
    server_lower = server.lower()
    is_common = any(kw.lower() in server_lower for kw in unusual_keywords)
    return not is_common
