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


async def build_evidence_bundle(
    target_url: str,
    canonical_url: Optional[str],
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
    leaf_form_fields: dict[str, list[dict]],
    leaf_visible_text: dict[str, str],
    leaf_titles: dict[str, str],
    lexical_risk_score: Optional[float] = None,
    passive_risk_score: Optional[float] = None,
    analyze_screenshots: bool = True,
) -> dict:
    """Produce un riepilogo compatto e strutturato dell'esplorazione.

    Parameters
    ----------
    leaf_form_fields:
        Mapping ``state_id_str → scan_form_fields()`` result for leaf states.
    leaf_visible_text:
        Mapping ``state_id_str → visible_text`` for leaf states (already
        stripped of script/style/markup, truncated to ~1500 chars).
    leaf_titles:
        Mapping ``state_id_str → document.title`` for leaf states.
    analyze_screenshots:
        Se True, per ogni stato foglia con ``screenshot_ref`` viene
        eseguito l'arricchimento Azure AI Vision (OCR + Brand Detection)
        e il risultato finisce nei campi ``ocr_text``/``brands`` della
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

    # ---- leaf states -------------------------------------------------------
    leaves: list[dict] = []
    # A state is a leaf when it has zero OUTbound transitions.
    from_state_ids = {str(t.from_state) for t in transitions}
    # Vision (OCR + Brand) sugli screenshot dei leaf: i task partono
    # TUTTI insieme (gather finale) invece che in sequenza — con N
    # foglie il costo passa da N×2-4s a ~1×2-4s nel full path.
    pending: dict[int, asyncio.Task] = {}
    for s in states:
        sid = str(s.id)
        if sid in from_state_ids:
            continue  # has outbound transitions → not a leaf
        leaf: dict = {
            "state_id": sid,
            "url": s.url,
            "depth": s.depth,
            "title": leaf_titles.get(sid, ""),
            "visible_text": leaf_visible_text.get(sid, ""),
            "form_fields": leaf_form_fields.get(sid, []),
            # Arricchimento Azure AI Vision — campi SEMPRE presenti
            # (anche vuoti) ma MAI fusi con visible_text: la provenienza
            # del testo resta distinguibile per il modello.
            "ocr_text": "",
            "brands": [],
        }
        if analyze_screenshots and s.screenshot_ref:
            pending[len(leaves)] = asyncio.create_task(
                analyze_screenshot(s.screenshot_ref)
            )
        leaves.append(leaf)

    if pending:
        results = await asyncio.gather(
            *pending.values(), return_exceptions=True
        )
        for idx, result in zip(pending.keys(), results):
            if isinstance(result, BaseException):
                # Leaf con Vision fallita → campi vuoti (stesso
                # comportamento del percorso sequenziale pre-refactor).
                continue
            leaves[idx]["ocr_text"] = result.get("ocr_text", "") or ""
            leaves[idx]["brands"] = result.get("brands", []) or []

    bundle["leaf_states"] = leaves

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
    lines.append("=== LEAF STATE DETAILS ===")
    for i, leaf in enumerate(bundle.get("leaf_states", []), start=1):
        lines.append(f"--- Leaf #{i} (depth {leaf['depth']}) ---")
        lines.append(f"  URL: {leaf['url']}")
        title = leaf.get("title", "")
        if title:
            lines.append(f"  Title: {title}")
        fields = leaf.get("form_fields", [])
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
        text = leaf.get("visible_text", "")
        if text:
            lines.append("  Testo visibile nel DOM (truncated):")
            # Indent the visible text for readability
            for tline in text.split("\n"):
                stripped = tline.strip()
                if stripped:
                    lines.append(f"    {stripped[:200]}")
        ocr_text = leaf.get("ocr_text", "")
        if ocr_text:
            # Provenienza DIVERSA dal visible_text: OCR sullo screenshot
            # (cattura anche testo renderizzato via canvas/immagini).
            lines.append("  Testo rilevato via OCR nello screenshot:")
            for tline in ocr_text.split("\n"):
                stripped = tline.strip()
                if stripped:
                    lines.append(f"    {stripped[:200]}")
        brands = leaf.get("brands", [])
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
