"""Costruzione della risposta binaria dell'API esterna (safe/malicious).

Mappa il Classification ternario interno (benign/suspicious/phishing)
nel verdetto binario atteso dal servizio chiamante, e produce la firma testuale
("signature") e l'azione raccomandata ("recommended_action").

Principio guida: **onestà**.  Se l'analisi non è completa, la risposta
lo dichiara esplicitamente — mai spacciare dati parziali per conclusivi.
"""

from __future__ import annotations

import json


from graph_engine.classifier.provider_warning import parse_kit_family
from graph_engine.models import Classification

# ---------------------------------------------------------------------------
# Mapping binario
# ---------------------------------------------------------------------------

# Il chiamante si aspetta solo "safe" o "malicious".
# In dubbio (suspicious) → safe: meglio un falso negativo che bloccare
# un sito legittimo.  La confidenza bassa e il rationale nel "reason"
# rendono trasparente l'incertezza.
#
# ECCEZIONE (2026-08-31): i suspicious con confidenza ≥
# ``_SUSPICIOUS_BLOCK_THRESHOLD`` (segnali deterministici FORTI e
# misurati — es. cloaking rilevato + infrastruttura abuse-prone, o TLS
# failure su hosting condiviso) vengono promossi a "malicious" in
# ``build_verdict_response``: mandare safe/allow su un quasi certo
# phishing è più costoso del raro falso positivo su un caso misurato.
VERDICT_MAP: dict = {
    Classification.benign: "safe",
    Classification.suspicious: "safe",
    Classification.phishing: "malicious",
}

# Soglia di promozione suspicious → malicious: confidenza ≥ soglia =
# segnali forti misurati, non dubbio debole.  Sotto soglia resta il
# comportamento storico (safe/allow, confidenza cappata a 0.5).
_SUSPICIOUS_BLOCK_THRESHOLD = 0.6

# ---------------------------------------------------------------------------
# Firme testuali
# ---------------------------------------------------------------------------

_SIG_BRAND = "Phishing: {brand} Impersonation"
_SIG_PROVIDER = "Flagged by {provider}: Suspected {kind}"
_SIG_MALWARE_DOWNLOAD = "Malware Download Lure: {brand} Impersonation"
_SIG_MALWARE_DOWNLOAD_GENERIC = "Malware Download Lure"
_SIG_GATE = "Suspicious Gate Bypass Detected"
_SIG_CREDENTIAL = "Credential Harvesting Detected"
_SIG_INCOMPLETE = "Analysis-Incomplete — Benign By Default"
_SIG_FAILED = "Analysis-Failed"
_SIG_SUSPICIOUS_BLOCK = "Suspicious Site Blocked"
_SIG_GENERIC = {
    "phishing": "Phishing Page Detected",
    "benign": "No Threats Detected",
    "suspicious": "Suspicious Site (Low Confidence)",
}

# ---------------------------------------------------------------------------
# build_signature
# ---------------------------------------------------------------------------


def build_signature(
    verdict,
    evidence: list[dict],
    *,
    mapped: str = "safe",
) -> str:
    """Costruisce la firma testuale per il verdetto binario.

    Le firme specifiche (brand impersonation, gate bypass, credential
    harvesting) descrivono un ATTACCO: vengono cercate SOLO quando il
    verdetto mappato è ``malicious``.  Su un verdetto ``safe`` una
    firma "Phishing: X Impersonation" sarebbe contraddittoria per il
    consumatore (caso reale: example.org classificato benign con
    ``verdict.brand="IANA"`` valorizzato da Foundry).

    Priorità di ricerca (la prima che matcha vince):

    1. **Brand impersonation**: cerca un brand noto nell'evidenza
       ``typosquat`` (L1) o nel campo ``verdict.brand``.
    2. **Gate bypass**: transizione ``gate_solved`` presente.
    3. **Credential harvesting**: evidenza ``aitm_email_payload`` (L1)
       o ``verdict.kit_family`` che contenga "aitm"/"harvest".
    4. **Firma generica** basata sulla classificazione.

    Nota: i campi form raggiungono il classificatore (bundle L5) ma NON
    sono persistiti come evidenza: la firma, ricostruita dal DB, usa per
    il rilevamento credenziali solo i segnali L1 persistiti e il
    ``kit_family`` del verdetto.
    """
    if mapped == "malicious":
        # 0. Pagina d'avviso del provider (regola deterministica del
        #    prefiltro): la firma dice chi ha segnalato il sito.
        flagged = parse_kit_family(getattr(verdict, "kit_family", None))
        if flagged is not None:
            provider, kind = flagged
            return _SIG_PROVIDER.format(
                provider=provider,
                kind="Phishing" if kind == "phishing" else "Malware",
            )

        # 0b. Esca per scaricare malware (finto installer/viewer/update):
        #     va distinta dal furto di credenziali per il chiamante.
        if (getattr(verdict, "kit_family", None) or "").lower() == "malware-download":
            v_brand = getattr(verdict, "brand", None)
            return (
                _SIG_MALWARE_DOWNLOAD.format(brand=v_brand)
                if v_brand else _SIG_MALWARE_DOWNLOAD_GENERIC
            )

        # 1. Brand impersonation — cerca nelle evidence con key="typosquat" (L1)
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
        #    (le evidence con key="gate_solved" vengono prodotte
        #    dall'explorer)
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
    if mapped == "malicious" and key == "suspicious":
        # Blocco da soglia (segnali forti) senza firma d'attacco
        # specifica: la firma "Low Confidence" sarebbe contraddittoria
        # su un verdetto malicious.
        return _SIG_SUSPICIOUS_BLOCK
    return _SIG_GENERIC.get(key, "Unclassified")


# ---------------------------------------------------------------------------
# build_verdict_response
# ---------------------------------------------------------------------------


def _wrap_result(payload: dict) -> dict:
    """Avvolge il payload nella chiave ``result`` del contratto.

    Il servizio chiamante legge il verdetto come ``result.verdict`` /
    ``result.signature``: i campi flat al livello superiore non vengono
    visti dal consumatore.  Il wrapper è quindi parte del contratto,
    non un dettaglio cosmetico.
    """
    return {"result": payload}


def build_verdict_response(data: dict | None) -> dict:
    """Costruisce la risposta dell'API esterna dal risultato dell'analisi.

    Args:
        data: Dizionario restituito da ``get_target_by_id()``, con chiavi
              ``target`` (AnalysisTarget), ``verdict`` (Verdict | None),
              ``evidence`` (list[Evidence]), ``states``, ``transitions``.
              Può essere ``None`` se l'analisi non è ancora iniziata.

    Returns:
        Un dict con la chiave ``result`` contenente le chiavi attese dal
        servizio chiamante: ``verdict``, ``confidence``, ``signature``,
        ``recommended_action``, ``reason``.
    """
    # ── Nessun dato ────────────────────────────────────────────────────
    if data is None:
        return _wrap_result({
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": "Analisi non ancora iniziata o dati non disponibili.",
        })

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
        return _wrap_result({
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_FAILED,
            "recommended_action": "allow",
            "reason": f"Analisi fallita: {error_detail}",
        })

    # ── Status running/queued ──────────────────────────────────────────
    if status_val in ("running", "queued"):
        return _wrap_result({
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": (
                f"Analisi ancora in corso (status: {status_val}). "
                "Riprova tra qualche minuto."
            ),
        })

    # ── Done senza verdict ─────────────────────────────────────────────
    if verdict is None:
        return _wrap_result({
            "verdict": "safe",
            "confidence": 0.1,
            "signature": _SIG_INCOMPLETE,
            "recommended_action": "allow",
            "reason": "Analisi completata ma classificazione assente.",
        })

    # ── Done con verdict ───────────────────────────────────────────────
    classification = getattr(verdict, "classification", None)
    confidence = getattr(verdict, "confidence", 0.0) or 0.0
    rationale = getattr(verdict, "rationale", None)

    mapped = (
        VERDICT_MAP.get(classification, "safe")
        if classification is not None
        else "safe"
    )

    # ── Blocco dei sospetti forti ──────────────────────────────────────
    # Un suspicious con confidenza alta è il prodotto di segnali
    # deterministici MISURATI (cloaking, infrastruttura abuse-prone):
    # promuoverlo a malicious evita di mandare safe/allow su un quasi
    # certo phishing.  Sotto soglia resta il dubbio debole → allow.
    if (
        mapped == "safe"
        and isinstance(classification, Classification)
        and classification == Classification.suspicious
        and confidence >= _SUSPICIOUS_BLOCK_THRESHOLD
    ):
        mapped = "malicious"

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

    signature = build_signature(verdict, evidence_dicts, mapped=mapped)

    reason = rationale or (
        "Analisi completata — nessun indicatore di phishing rilevato."
        if mapped == "safe"
        else "Indicatori di phishing confermati."
    )

    return _wrap_result({
        "verdict": mapped,
        "confidence": confidence,
        "signature": signature,
        "recommended_action": action,
        "reason": reason,
    })


def entry_response(entry: dict) -> dict:
    """Costruisce una risposta immediata da un hit allowlist/blacklist.

    Args:
        entry: Dizionario restituito da ``allowlist.check_domain()`` /
               ``check_url_and_domain()``, con chiavi ``list_type``,
               ``note`` e (opzionale) ``matched`` (``"url"`` | ``"domain"``).
               Senza ``matched`` il livello si assume "domain" — le
               firme storiche restano invariate.

    Returns:
        Dict pronto per essere restituito come JSON.
    """
    list_type = entry["list_type"]
    note = entry.get("note")
    # Livello del match ("url" | "domain"): le firme restano in inglese
    # (contratto col chiamante), il reason di default in italiano.
    level = "URL" if entry.get("matched") == "url" else "Domain"
    level_it = "URL" if level == "URL" else "Dominio"

    if list_type == "whitelist":
        return _wrap_result({
            "verdict": "safe",
            "confidence": 1.0,
            "signature": f"Whitelist-Override: {level} explicitly trusted",
            "recommended_action": "allow",
            "reason": note or f"{level_it} in whitelist — analisi bypassata.",
        })
    else:
        return _wrap_result({
            "verdict": "malicious",
            "confidence": 1.0,
            "signature": f"Blacklist-Override: {level} explicitly blocked",
            "recommended_action": "block",
            "reason": note or f"{level_it} in blacklist — analisi bypassata.",
        })
