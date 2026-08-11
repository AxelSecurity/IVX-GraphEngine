"""CLI entry point — explore a URL and dump the resulting graph as JSON.

Usage::

    python -m graph_engine.cli <url> [--max-depth N] [--max-nodes N] [--timeout N]
                                     [--no-artifacts] [--top-n-actions N]
                                     [--classify]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from typing import Optional

from playwright.async_api import async_playwright

from graph_engine.budget import Budget
from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import AnalysisTarget, Evidence, State, Transition, Verdict


def _serialise(target: AnalysisTarget, states: list[State],
               transitions: list[Transition],
               evidence: list[Evidence],
               verdict: Optional[Verdict] = None) -> str:
    """Produce an indented JSON representation of the full graph."""
    payload = {
        "target": target.model_dump(mode="json"),
        "states": [s.model_dump(mode="json") for s in states],
        "transitions": [t.model_dump(mode="json") for t in transitions],
        "evidence": [e.model_dump(mode="json") for e in evidence],
    }
    if verdict is not None:
        payload["verdict"] = verdict.model_dump(mode="json")
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# L5 classification helpers (only imported / used when --classify is set)
# ---------------------------------------------------------------------------


def _extract_visible_text(html: str) -> str:
    """Strip scripts, styles, tags, and extra whitespace; truncate to ~1500 chars."""
    # Remove <script>, <style>, <noscript> blocks entirely
    text = re.sub(r'<(script|style|noscript)\b[^>]*>.*?</\1>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    # Remove remaining HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Decode common entities
    text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    text = text.replace('&quot;', '"').replace('&#x27;', "'").replace('&nbsp;', ' ')
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:1500]


async def _run_classification(
    target: AnalysisTarget,
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
) -> Optional[Verdict]:
    """Build evidence bundle, run prefilter + classifier, return Verdict."""
    import os

    from graph_engine.classifier.evidence_bundle import build_evidence_bundle
    from graph_engine.classifier.prefilter import prefilter

    # ---- leaf detection (state has no OUTbound transitions) -----------------
    from_state_ids = {str(t.from_state) for t in transitions}
    leaf_states = [s for s in states if str(s.id) not in from_state_ids]

    # ---- scrape leaf pages for visible text, titles, form fields ---------
    leaf_form_fields: dict[str, list[dict]] = {}
    leaf_visible_text: dict[str, str] = {}
    leaf_titles: dict[str, str] = {}

    # For the CLI we read DOM snapshots from disk when available;
    # otherwise we leave fields/text empty (still useful with URLs + titles).
    for s in leaf_states:
        sid = str(s.id)
        leaf_form_fields[sid] = []
        leaf_visible_text[sid] = ""
        leaf_titles[sid] = ""

        # Try to read DOM snapshot from disk
        if s.har_ref:
            dom_path = os.path.join(
                os.path.dirname(s.har_ref), "dom.html"
            )
            if os.path.isfile(dom_path):
                try:
                    with open(dom_path, encoding="utf-8") as fh:
                        html = fh.read()
                except Exception:
                    html = ""
                if html:
                    # Extract title
                    title_match = re.search(r'<title[^>]*>(.*?)</title>',
                                            html, re.DOTALL | re.IGNORECASE)
                    if title_match:
                        leaf_titles[sid] = title_match.group(1).strip()
                    leaf_visible_text[sid] = _extract_visible_text(html)

    # ---- bundle -----------------------------------------------------------
    bundle = build_evidence_bundle(
        target_url=target.input_url,
        canonical_url=target.canonical_url,
        states=states,
        transitions=transitions,
        evidence=evidence,
        leaf_form_fields=leaf_form_fields,
        leaf_visible_text=leaf_visible_text,
        leaf_titles=leaf_titles,
    )
    # Inject target_id for the classifier
    bundle["target_id"] = str(target.id)

    # ---- prefilter → classifier -------------------------------------------
    verdict = prefilter(bundle)
    if verdict is not None:
        return verdict

    from graph_engine.classifier.foundry_classifier import classify

    # Collect screenshot paths for leaf states
    screenshot_paths: list[str] = []
    for s in leaf_states:
        if s.screenshot_ref and os.path.isfile(s.screenshot_ref):
            screenshot_paths.append(s.screenshot_ref)

    return await classify(bundle, screenshot_paths)


# ---------------------------------------------------------------------------
# Async entry point
# ---------------------------------------------------------------------------


async def _main(args: argparse.Namespace) -> None:
    budget = Budget(
        max_depth=args.max_depth,
        max_nodes=args.max_nodes,
        timeout_s=args.timeout,
    )

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                args.url,
                budget=budget,
                capture_artifacts=not args.no_artifacts,
                top_n_actions=args.top_n_actions,
            )

            verdict: Optional[Verdict] = None
            if args.classify:
                logging.info("Running L5 classification…")
                verdict = await _run_classification(
                    target,
                    explorer.states,
                    explorer.transitions,
                    explorer.evidence,
                )
                if verdict:
                    logging.info(
                        "Classification: %s (confidence=%.2f)",
                        verdict.classification.value,
                        verdict.confidence,
                    )

            print(_serialise(target, explorer.states, explorer.transitions,
                             explorer.evidence, verdict))
        finally:
            await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IVX GraphEngine — BFS state-graph explorer",
    )
    parser.add_argument(
        "url",
        help="Starting URL to explore",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="Maximum BFS depth (default: 6)",
    )
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=40,
        help="Maximum total states (default: 40)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Wall-clock timeout in seconds (default: 180)",
    )
    parser.add_argument(
        "--no-artifacts",
        action="store_true",
        help="Disable per-state artifact capture (HAR, screenshot, DOM)",
    )
    parser.add_argument(
        "--top-n-actions",
        type=int,
        default=3,
        help="Max click candidates attempted per state (default: 3, 0 = disable)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging for the entire exploration",
    )
    parser.add_argument(
        "--classify",
        action="store_true",
        help="Run L5 classification after exploration (requires Azure Foundry or falls back to heuristics)",
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stderr,
        )

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
