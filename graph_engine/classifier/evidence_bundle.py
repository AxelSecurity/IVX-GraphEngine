"""Compact evidence bundle for the L5 classifier.

The bundle is a plain dict (no Pydantic model) intentionally kept
lightweight — it never carries raw DOM, HAR dumps, or screenshot
bytes directly.  Those stay on disk; the bundle references them by
path when needed.

Rationale: the Foundry Agent has a context-window budget.  We send
structured *observations*, not data.
"""

from __future__ import annotations

from typing import Optional

from graph_engine.models import Evidence, State, Transition


def build_evidence_bundle(
    target_url: str,
    canonical_url: Optional[str],
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
    leaf_form_fields: dict[str, list[dict]],
    leaf_visible_text: dict[str, str],
    leaf_titles: dict[str, str],
) -> dict:
    """Produce a compact, structured summary of the exploration.

    Parameters
    ----------
    leaf_form_fields:
        Mapping ``state_id_str → scan_form_fields()`` result for leaf states.
    leaf_visible_text:
        Mapping ``state_id_str → visible_text`` for leaf states (already
        stripped of script/style/markup, truncated to ~1500 chars).
    leaf_titles:
        Mapping ``state_id_str → document.title`` for leaf states.
    """

    # ---- basics -----------------------------------------------------------
    bundle: dict = {
        "input_url": target_url,
        "canonical_url": canonical_url,
        "num_states": len(states),
        "num_transitions": len(transitions),
        "max_depth_reached": max((s.depth for s in states), default=0),
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

    # ---- leaf states -------------------------------------------------------
    leaves: list[dict] = []
    # A state is a leaf when it has zero OUTbound transitions.
    from_state_ids = {str(t.from_state) for t in transitions}
    for s in states:
        sid = str(s.id)
        if sid in from_state_ids:
            continue  # has outbound transitions → not a leaf
        leaves.append({
            "state_id": sid,
            "url": s.url,
            "depth": s.depth,
            "title": leaf_titles.get(sid, ""),
            "visible_text": leaf_visible_text.get(sid, ""),
            "form_fields": leaf_form_fields.get(sid, []),
        })
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
            lines.append("  Visible text (truncated):")
            # Indent the visible text for readability
            for tline in text.split("\n"):
                stripped = tline.strip()
                if stripped:
                    lines.append(f"    {stripped[:200]}")
        lines.append("")

    return "\n".join(lines)
