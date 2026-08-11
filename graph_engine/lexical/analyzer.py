"""Orchestratore L1 — analisi lessicale / statica.

Coordina typosquat, DGA entropy, pattern infrastrutturali, IP literal,
mixed-script, e segnale AiTM da payload email nidificato.

Restituisce evidenze e un punteggio di rischio grezzo 0-1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from graph_engine.lexical.entropy import dga_score
from graph_engine.lexical.infra_patterns import (
    check_abuse_prone_infra,
    has_mixed_script,
    is_ip_literal,
)
from graph_engine.lexical.typosquat import check_typosquat

# ---------------------------------------------------------------------------
# Pesi per il lexical_risk_score
# ---------------------------------------------------------------------------
# Somma pesata di tutti i segnali L1, clampata a [0, 1].
# I pesi sono volutamente non lineari — un singolo segnale forte
# (es. AiTM email) pesa più di due segnali deboli messi insieme.

_W_TYPOSQUAT_D1 = 0.30   # distanza 1 (differenza di 1 carattere)
_W_TYPOSQUAT_D2 = 0.15   # distanza 2
_W_DGA = 0.25             # DGA score > 0.6
_W_ABUSE_INFRA = 0.20     # infrastruttura abuse-prone
_W_IP_LITERAL = 0.15      # IP literal invece di hostname
_W_MIXED_SCRIPT = 0.25    # mescolanza di script (omoglifi)
_W_AITM_EMAIL = 0.40      # payload email nidificato (segnale forte AiTM)

# Soglia DGA per considerare il segnale significativo
_DGA_SIGNAL_THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evidence(
    key: str,
    value: Any,
    weight: float,
) -> dict:
    """Costruisce un dizionario evidenza L1 pronto per ``Evidence(**kw)``."""
    return {
        "scope": "target",
        "layer": "L1",
        "key": key,
        "value": value,
        "weight": weight,
        "produced_by": "lexical",
        "ts": datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# Orchestratore principale
# ---------------------------------------------------------------------------


def analyze(
    canonical_url: str,
    nested_payloads: list[dict],
) -> dict:
    """Esegue tutte le euristiche L1 su *canonical_url*.

    Parametri
    ---------
    canonical_url : str
        URL normalizzato (output di L0 canonicalize).
    nested_payloads : list[dict]
        Payload nidificati estratti da L0 (campo ``nested_payloads``
        del risultato di ``ingest()``).

    Ritorna
    -------
    dict con chiavi:
        evidence : list[dict]
            Una entry per ogni segnale trovato (MAI per l'assenza).
        lexical_risk_score : float
            Punteggio grezzo 0-1, somma pesata clampata.
    """
    parsed = urlparse(canonical_url)
    hostname = parsed.hostname or ""
    evidence: list[dict] = []
    risk = 0.0

    # --- Typosquat / brand impersonation ---
    typosquat: Optional[dict] = None
    if hostname:
        typosquat = check_typosquat(hostname)
    if typosquat is not None:
        weight = _W_TYPOSQUAT_D1 if typosquat["distance"] == 1 else _W_TYPOSQUAT_D2
        risk += weight
        evidence.append(_make_evidence(
            key="typosquat",
            value=typosquat,
            weight=weight,
        ))

    # --- DGA entropy ---
    dga = 0.0
    if hostname:
        dga = dga_score(hostname)
    if dga > _DGA_SIGNAL_THRESHOLD:
        risk += _W_DGA
        evidence.append(_make_evidence(
            key="dga_score",
            value={"score": dga, "hostname": hostname},
            weight=_W_DGA,
        ))

    # --- Infrastruttura abuse-prone ---
    infra_cat: Optional[str] = None
    if hostname:
        infra_cat = check_abuse_prone_infra(hostname)
    if infra_cat is not None:
        risk += _W_ABUSE_INFRA
        evidence.append(_make_evidence(
            key="abuse_prone_infra",
            value={"category": infra_cat, "hostname": hostname},
            weight=_W_ABUSE_INFRA,
        ))

    # --- IP literal ---
    is_ip = False
    if hostname:
        is_ip = is_ip_literal(hostname)
    if is_ip:
        risk += _W_IP_LITERAL
        evidence.append(_make_evidence(
            key="ip_literal",
            value={"hostname": hostname},
            weight=_W_IP_LITERAL,
        ))

    # --- Mixed-script / omoglifi ---
    mixed = False
    if hostname:
        mixed = has_mixed_script(hostname)
    if mixed:
        risk += _W_MIXED_SCRIPT
        evidence.append(_make_evidence(
            key="mixed_script",
            value={"hostname": hostname},
            weight=_W_MIXED_SCRIPT,
        ))

    # --- Payload email nidificato (segnale AiTM) ---
    email_payloads = [
        p for p in nested_payloads
        if p.get("kind") == "email"
    ]
    if email_payloads:
        risk += _W_AITM_EMAIL
        evidence.append(_make_evidence(
            key="aitm_email_payload",
            value={
                "count": len(email_payloads),
                "emails": [p.get("decoded") for p in email_payloads],
            },
            weight=_W_AITM_EMAIL,
        ))

    # --- DGA score "borderline" come segnale informativo ---
    # (solo se non ha già triggerato il segnale forte)
    if dga > 0.3 and dga <= _DGA_SIGNAL_THRESHOLD and hostname:
        evidence.append(_make_evidence(
            key="dga_borderline",
            value={"score": dga, "hostname": hostname},
            weight=0.0,  # non contribuisce al rischio, solo informativo
        ))

    return {
        "evidence": evidence,
        "lexical_risk_score": round(min(1.0, risk), 4),
    }
