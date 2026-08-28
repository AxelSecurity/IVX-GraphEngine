"""Compact evidence bundle for the L5 classifier.

The bundle is a plain dict (no Pydantic model) intentionally kept
lightweight — it never carries raw DOM, HAR dumps, or screenshot
bytes directly.  Those stay on disk; the bundle references them by
path when needed.

Rationale: the Foundry Agent has a context-window budget.  We send
structured *observations*, not data.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from graph_engine.classifier.vision_analysis import analyze_screenshot
from graph_engine.models import Evidence, State, Transition

# Evidence keys that carry signal on their own (L1/L2/L3).  Their values
# are extracted into ``bundle["strong_evidence_details"]`` so that
# value-dependent prefilter rules (typosquat distance == 1) can run.
# Keep in sync with graph_engine.classifier.prefilter.
_STRONG_EVIDENCE_KEYS = ("typosquat", "reputation_hit", "cloaking_detected")


def _coerce_evidence_value(value):
    """Coerce an ``Evidence.value`` (str) back to structured data when it
    is JSON-serialised — needed for value-dependent rules."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value


# Marker degli errori TLS (certificato non valido per l'hostname) nei
# valori delle evidenze.  Compare sia nel ``navigation_error`` dell'explorer
# (net::ERR_CERT_* di Chromium) sia nelle ``active_probe_error`` L3
# (CERTIFICATE_VERIFY_FAILED della sonda redirect_chain, con "Hostname
# mismatch" di urllib3/ssl).  Confronto case-insensitive sul valore
# uppercasato.
_TLS_ERROR_MARKERS = ("ERR_CERT", "CERTIFICATE_VERIFY_FAILED", "HOSTNAME MISMATCH")


def _has_tls_marker(value) -> bool:
    """True se il valore di un'evidenza contiene un errore TLS."""
    if isinstance(value, str):
        upper = value.upper()
        return any(marker in upper for marker in _TLS_ERROR_MARKERS)
    return False


async def build_evidence_bundle(
    target_url: str,
    canonical_url: Optional[str],
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
    form_fields_by_state: dict[str, list[dict]],
    visible_text_by_state: dict[str, str],
    titles_by_state: dict[str, str],
    lexical_risk_score: Optional[float] = None,
    passive_risk_score: Optional[float] = None,
    analyze_screenshots: bool = True,
) -> dict:
    """Produce un riepilogo compatto e strutturato dell'esplorazione.

    Parameters
    ----------
    form_fields_by_state:
        Mapping ``state_id_str → scan_form_fields()`` result — per OGNI
        stato del grafo (intermedio e terminale).
    visible_text_by_state:
        Mapping ``state_id_str → visible_text`` (already stripped of
        script/style/markup, truncated to ~1500 chars) — per ogni stato.
    titles_by_state:
        Mapping ``state_id_str → document.title`` — per ogni stato.
    analyze_screenshots:
        Se True, per ogni stato con ``screenshot_ref`` viene eseguito
        l'arricchimento Azure AI Vision (OCR + Brand Detection) e il
        risultato finisce nei campi ``ocr_text``/``brands`` della
        entry — MAI fuso con ``visible_text`` (provenienza distinta).
    """

    # ---- basics -----------------------------------------------------------
    bundle: dict = {
        "input_url": target_url,
        "canonical_url": canonical_url,
        "num_states": len(states),
        "num_transitions": len(transitions),
        "max_depth_reached": max((s.depth for s in states), default=0),
        # Raw L1/L2 risk scores — the prefilter needs them to decide
        # whether L4 sparsity is really "insufficient data" or just a
        # case where the signal lives in the other layers.
        "lexical_risk_score": lexical_risk_score,
        "passive_risk_score": passive_risk_score,
    }

    # ---- transition-kind counts -------------------------------------------
    kind_counts: dict[str, int] = {}
    for t in transitions:
        kind = t.kind.value if hasattr(t.kind, "value") else str(t.kind)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    bundle["transition_kinds_seen"] = kind_counts

    # ---- flags from Evidence -----------------------------------------------
    evidence_keys = {e.key for e in evidence}
    bundle["flags"] = {
        "had_gate": "blocked_by_gate" in evidence_keys,
        "had_navigation_error": "navigation_error" in evidence_keys,
        "had_replay_fallback": "replay_fallback_used" in evidence_keys,
        "had_unhandled_error": "unhandled_node_error" in evidence_keys,
        # Errore TLS (certificato non valido per l'hostname): segnale
        # deterministico per il prefilter, anche quando l'esplorazione
        # procede comunque (ignore_https_errors) e il navigation_error
        # non viene prodotto.
        "had_tls_error": any(
            _has_tls_marker(getattr(e, "value", "") or "")
            for e in evidence
            if e.key in ("navigation_error", "active_probe_error")
        ),
    }

    # ---- evidence summary (key → count, for debugging) ---------------------
    ev_summary: dict[str, int] = {}
    for e in evidence:
        ev_summary[e.key] = ev_summary.get(e.key, 0) + 1
    bundle["evidence_summary"] = ev_summary

    # ---- strong evidence details (L1/L2/L3 keys the prefilter needs) -------
    strong_details: dict[str, list] = {}
    for e in evidence:
        if e.key in _STRONG_EVIDENCE_KEYS:
            strong_details.setdefault(e.key, []).append(
                _coerce_evidence_value(e.value)
            )
    bundle["strong_evidence_details"] = strong_details

    # ---- ALL graph states (intermediate + terminal) ------------------------
    # Ogni stato del grafo finisce nel bundle, NON solo le foglie: una
    # pagina di phishing con una transizione in uscita (es. un link
    # legittimo "Serve aiuto?" verso il sito ufficiale) deve restare
    # visibile al classificatore.  ``is_leaf`` descrive la topologia ma
    # NON filtra il contenuto.
    from_state_ids = {str(t.from_state) for t in transitions}
    state_entries: list[dict] = []
    # Vision (OCR + Brand) sugli screenshot: i task partono TUTTI
    # insieme (gather finale) invece che in sequenza — con N stati il
    # costo passa da N×2-4s a ~1×2-4s nel full path.
    pending: dict[int, asyncio.Task] = {}
    for s in states:
        sid = str(s.id)
        entry: dict = {
            "state_id": sid,
            "url": s.url,
            "depth": s.depth,
            "is_leaf": sid not in from_state_ids,
            "title": titles_by_state.get(sid, ""),
            "visible_text": visible_text_by_state.get(sid, ""),
            "form_fields": form_fields_by_state.get(sid, []),
            # Arricchimento Azure AI Vision — campi SEMPRE presenti
            # (anche vuoti) ma MAI fusi con visible_text: la provenienza
            # del testo resta distinguibile per il modello.
            "ocr_text": "",
            "brands": [],
        }
        if analyze_screenshots and s.screenshot_ref:
            pending[len(state_entries)] = asyncio.create_task(
                analyze_screenshot(s.screenshot_ref)
            )
        state_entries.append(entry)

    if pending:
        results = await asyncio.gather(
            *pending.values(), return_exceptions=True
        )
        for idx, result in zip(pending.keys(), results):
            if isinstance(result, BaseException):
                # Stato con Vision fallita → campi vuoti (stesso
                # comportamento del percorso sequenziale pre-refactor).
                continue
            state_entries[idx]["ocr_text"] = result.get("ocr_text", "") or ""
            state_entries[idx]["brands"] = result.get("brands", []) or []

    bundle["states"] = state_entries

    return bundle


def bundle_to_prompt_text(bundle: dict) -> str:
    """Serialize *bundle* into readable, structured text for the model prompt.

    The output is deliberately *not* raw JSON — it is formatted as labeled
    sections so a language model can parse it reliably even if the JSON
    structure shifts between versions.
    """
    lines: list[str] = []

    lines.append("=== EXPLORATION SUMMARY ===")
    lines.append(f"Input URL: {bundle['input_url']}")
    if bundle.get("canonical_url"):
        lines.append(f"Canonical URL: {bundle['canonical_url']}")
    lines.append(f"States visited: {bundle['num_states']}")
    lines.append(f"Transitions recorded: {bundle['num_transitions']}")
    lines.append(f"Max depth reached: {bundle['max_depth_reached']}")
    if bundle.get("lexical_risk_score") is not None:
        lines.append(f"Lexical risk score (L1): {bundle['lexical_risk_score']}")
    if bundle.get("passive_risk_score") is not None:
        lines.append(f"Passive risk score (L2): {bundle['passive_risk_score']}")

    lines.append("")
    lines.append("=== TRANSITION TYPES ===")
    for kind, count in sorted(bundle.get("transition_kinds_seen", {}).items()):
        lines.append(f"  {kind}: {count}")

    lines.append("")
    lines.append("=== FLAGS (from Evidence) ===")
    for flag, value in sorted(bundle.get("flags", {}).items()):
        lines.append(f"  {flag}: {value}")

    lines.append("")
    lines.append("=== EVIDENCE COUNTS ===")
    for key, count in sorted(bundle.get("evidence_summary", {}).items()):
        lines.append(f"  {key}: {count}")

    lines.append("")
    lines.append("=== STATE DETAILS (every explored state) ===")
    for i, st in enumerate(bundle.get("states", []), start=1):
        if st.get("is_leaf"):
            terminus = "foglia — nessuna ulteriore azione"
        else:
            terminus = "proseguito con altre azioni"
        lines.append(f"--- State #{i} ---")
        lines.append(f"  Depth: {st['depth']} ({terminus})")
        lines.append(f"  URL: {st['url']}")
        title = st.get("title", "")
        if title:
            lines.append(f"  Title: {title}")
        fields = st.get("form_fields", [])
        if fields:
            lines.append(f"  Form fields detected ({len(fields)}):")
            for f in fields:
                label = f.get("nearby_label_text", "")
                label_str = f'  → "{label}"' if label else ""
                lines.append(
                    f"    {f['tag']}[type={f['type']}]"
                    f"  name_or_id={f['name_or_id']}{label_str}"
                )
        else:
            lines.append("  Form fields: none")
        text = st.get("visible_text", "")
        if text:
            lines.append("  Testo visibile nel DOM (truncated):")
            # Indent the visible text for readability
            for tline in text.split("\n"):
                stripped = tline.strip()
                if stripped:
                    lines.append(f"    {stripped[:200]}")
        ocr_text = st.get("ocr_text", "")
        if ocr_text:
            # Provenienza DIVERSA dal visible_text: OCR sullo screenshot
            # (cattura anche testo renderizzato via canvas/immagini).
            lines.append("  Testo rilevato via OCR nello screenshot:")
            for tline in ocr_text.split("\n"):
                stripped = tline.strip()
                if stripped:
                    lines.append(f"    {stripped[:200]}")
        brands = st.get("brands", [])
        if brands:
            lines.append("  Brand rilevati nello screenshot:")
            for brand in brands:
                if not isinstance(brand, dict):
                    continue
                name = brand.get("name", "?")
                confidence = brand.get("confidence", 0.0)
                lines.append(f"    - {name} (confidence {confidence:.2f})")
        lines.append("")

    return "\n".join(lines)
