"""Costruzione della risposta binaria Trellix (safe/malicious).

Mappa il Classification ternario interno (benign/suspicious/phishing)
nel verdetto binario atteso da Trellix, e produce la firma testuale
("signature") e l'azione raccomandata ("recommended_action").

Principio guida: **onestà**.  Se l'analisi non è completa, la risposta
lo dichiara esplicitamente — mai spacciare dati parziali per conclusivi.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import yaml

from graph_engine.models import Classification

# ---------------------------------------------------------------------------
# Mapping binario
# ---------------------------------------------------------------------------

# Trellix si aspetta solo "safe" o "malicious".
# In dubbio (suspicious) → safe: meglio un falso negativo che bloccare
# un sito legittimo.  La confidenza bassa e il rationale nel "reason"
# rendono trasparente l'incertezza.
VERDICT_MAP: dict = {
    Classification.benign: "safe",
    Classification.suspicious: "safe",
    Classification.phishing: "malicious",
}

# ---------------------------------------------------------------------------
# Firme testuali
# ---------------------------------------------------------------------------

_SIG_BRAND = "Phishing: {brand} Impersonation"
_SIG_GATE = "Suspicious Gate Bypass Detected"
_SIG_CREDENTIAL = "Credential Harvesting Detected"
_SIG_INCOMPLETE = "Analysis-Incomplete — Benign By Default"
_SIG_FAILED = "Analysis-Failed"
_SIG_GENERIC = {
    "phishing": "Phishing Page Detected",
    "benign": "No Threats Detected",
    "suspicious": "Suspicious Site (Low Confidence)",
}

# ---------------------------------------------------------------------------
# Caricamento brand (lazy, module-level cache)
# ---------------------------------------------------------------------------

_BRANDS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "lexical", "data", "brands.yaml",
)

_BRAND_NAMES: set[str] | None = None


def _get_brand_names() -> set[str]:
    """Carica i nomi dei brand dal file YAML una volta sola."""
    global _BRAND_NAMES
    if _BRAND_NAMES is not None:
        return _BRAND_NAMES

    _BRAND_NAMES = set()
    try:
        with open(_BRANDS_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "brand" in entry:
                    _BRAND_NAMES.add(entry["brand"])
    except Exception:
        # Se il file non esiste o è corrotto, insieme vuoto → firma generica
        pass
    return _BRAND_NAMES


# ---------------------------------------------------------------------------
# build_signature
# ---------------------------------------------------------------------------


def build_signature(
    verdict,
    evidence: list[dict],
) -> str:
    """Costruisce la firma testuale per il verdetto Trellix.

    Priorità di ricerca (la prima che matcha vince):

    1. **Brand impersonation**: cerca un brand noto nell'evidenza
       ``typosquat`` (L1) o nel campo ``verdict.brand``.
    2. **Gate bypass**: transizione ``gate_solved`` presente.
    3. **Credential harvesting**: evidenza ``aitm_email_payload`` (L1)
       o ``verdict.kit_family`` che contenga "aitm"/"harvest".
    4. **Firma generica** basata sulla classificazione.

    Nota: i form fields NON sono persistiti come evidenza
    (``pipeline_runner._run_classification`` li inizializza a ``[]``),
    quindi il rilevamento credenziali usa solo i segnali L1 persistiti.
    """
    # 1. Brand impersonation
    brand_names = _get_brand_names()

    # Cerca nelle evidence con key="typosquat" (L1)
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("key") == "typosquat":
            value = ev.get("value", "")
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(parsed, dict) and "brand" in parsed:
                    return _SIG_BRAND.format(brand=parsed["brand"])
            elif isinstance(value, dict) and "brand" in value:
                return _SIG_BRAND.format(brand=value["brand"])

    # Cerca nel verdict.brand
    v_brand = getattr(verdict, "brand", None)
    if v_brand:
        return _SIG_BRAND.format(brand=v_brand)

    # 2. Gate bypass — cerca transition con kind="gate_solved"
    #    (le evidence con key="gate_solved" vengono prodotte dall'explorer)
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("key") == "gate_solved":
            return _SIG_GATE

    # 3. Credential harvesting — evidenza L1 "aitm_email_payload"
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("key") == "aitm_email_payload":
            return _SIG_CREDENTIAL

    # Anche kit_family sul verdict
    kit = getattr(verdict, "kit_family", None)
    if kit and any(kw in kit.lower() for kw in ("aitm", "harvest", "evilginx")):
        return _SIG_CREDENTIAL

    # 4. Firma generica
    classification = (
        getattr(verdict, "classification", None)
        if verdict is not None
        else None
    )
    if isinstance(classification, Classification):
        key = classification.value
    elif isinstance(classification, str):
        key = classification
    else:
        key = "suspicious"
    return _SIG_GENERIC.get(key, "Unclassified")


# ---------------------------------------------------------------------------
# build_trellix_response
# ---------------------------------------------------------------------------


def build_trellix_response(
    data: dict | None,
    *,
    timed_out: bool = False,
) -> dict:
    """Costruisce la risposta Trellix dal risultato dell'analisi.

    Args:
        data: Dizionario restituito da ``get_target_by_id()``, con chiavi
              ``target`` (AnalysisTarget), ``verdict`` (Verdict | None),
              ``evidence`` (list[Evidence]), ``states``, ``transitions``.
              Può essere ``None`` se l'analisi non è ancora iniziata.
        timed_out: Se ``True``, forza la risposta "incompleta" anche se
                   l'analisi è effettivamente terminata nel frattempo
                   (usato quando il wrapper ha già deciso di rispondere
                   prima del completamento).

    Returns:
        Un dict con le chiavi attese da Trellix:
        ``verdict``, ``confidence``, ``signature``,
        ``recommended_action``, ``reason``.
    """
    # ── Timeout ────────────────────────────────────────────────────────
    if timed_out:
        return {
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": (
                "L'analisi non è terminata entro la finestra di tempo "
                "Trellix (60s). Il risultato sarà disponibile a breve "
                "interrogando l'endpoint REST /analyses/{id}. "
                "Questa risposta è deliberatamente safe per non bloccare "
                "l'utente su un'analisi incompleta."
            ),
        }

    # ── Nessun dato ────────────────────────────────────────────────────
    if data is None:
        return {
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": "Analisi non ancora iniziata o dati non disponibili.",
        }

    target = data.get("target")
    verdict = data.get("verdict")
    evidence_raw = data.get("evidence", [])

    # Converti gli oggetti Evidence in dict per build_signature
    evidence_dicts: list[dict] = []
    for ev in evidence_raw:
        if hasattr(ev, "model_dump"):
            evidence_dicts.append(ev.model_dump(mode="json"))
        elif isinstance(ev, dict):
            evidence_dicts.append(ev)

    # ── Status error ───────────────────────────────────────────────────
    target_status = getattr(target, "status", None)
    if target_status is not None:
        status_val = (
            target_status.value
            if hasattr(target_status, "value")
            else str(target_status)
        )
    else:
        status_val = "unknown"

    if status_val == "error":
        # Cerca l'evidenza pipeline_error per includerla nel reason
        error_detail = "Errore sconosciuto durante l'analisi."
        for ev in evidence_dicts:
            if ev.get("key") == "pipeline_error":
                error_detail = str(ev.get("value", error_detail))
                break
        return {
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_FAILED,
            "recommended_action": "allow",
            "reason": f"Analisi fallita: {error_detail}",
        }

    # ── Status running/queued ──────────────────────────────────────────
    if status_val in ("running", "queued"):
        return {
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": (
                f"Analisi ancora in corso (status: {status_val}). "
                "Riprova tra qualche minuto."
            ),
        }

    # ── Done senza verdict ─────────────────────────────────────────────
    if verdict is None:
        return {
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": "Analisi completata ma classificazione assente.",
        }

    # ── Done con verdict ───────────────────────────────────────────────
    classification = getattr(verdict, "classification", None)
    confidence = getattr(verdict, "confidence", 0.0) or 0.0
    rationale = getattr(verdict, "rationale", None)

    mapped = (
        VERDICT_MAP.get(classification, "safe")
        if classification is not None
        else "safe"
    )

    if mapped == "malicious":
        confidence = round(max(0.8, confidence), 2)
        action = "block"
    else:
        # suspicious → safe: confidenza ridotta, dichiarata onestamente
        if (
            isinstance(classification, Classification)
            and classification == Classification.suspicious
        ):
            confidence = round(min(0.5, confidence or 0.4), 2)
        else:
            confidence = round(max(0.9, confidence), 2)
        action = "allow"

    signature = build_signature(verdict, evidence_dicts)

    reason = rationale or (
        "Analisi completata — nessun indicatore di phishing rilevato."
        if mapped == "safe"
        else "Indicatori di phishing confermati."
    )

    return {
        "verdict": mapped,
        "confidence": confidence,
        "signature": signature,
        "recommended_action": action,
        "reason": reason,
    }


def entry_response(entry: dict) -> dict:
    """Costruisce una risposta Trellix immediata da un hit allowlist/blacklist.

    Args:
        entry: Dizionario restituito da ``allowlist.check_domain()``,
               con chiavi ``list_type`` e ``note``.

    Returns:
        Dict Trellix pronto per essere restituito come JSON.
    """
    list_type = entry["list_type"]
    note = entry.get("note")

    if list_type == "whitelist":
        return {
            "verdict": "safe",
            "confidence": 1.0,
            "signature": "Whitelist-Override: Domain explicitly trusted",
            "recommended_action": "allow",
            "reason": note or "Dominio in whitelist — analisi bypassata.",
        }
    else:
        return {
            "verdict": "malicious",
            "confidence": 1.0,
            "signature": "Blacklist-Override: Domain explicitly blocked",
            "recommended_action": "block",
            "reason": note or "Dominio in blacklist — analisi bypassata.",
        }
