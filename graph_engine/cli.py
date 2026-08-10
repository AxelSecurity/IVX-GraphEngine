"""CLI entry point — explore a URL and dump the resulting graph as JSON.

Usage::

    python -m graph_engine.cli <url> [--max-depth N] [--max-nodes N] [--timeout N]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from playwright.async_api import async_playwright

from graph_engine.budget import Budget
from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import AnalysisTarget, Evidence, State, Transition


def _serialise(target: AnalysisTarget, states: list[State],
               transitions: list[Transition],
               evidence: list[Evidence]) -> str:
    """Produce an indented JSON representation of the full graph."""
    payload = {
        "target": target.model_dump(mode="json"),
        "states": [s.model_dump(mode="json") for s in states],
        "transitions": [t.model_dump(mode="json") for t in transitions],
        "evidence": [e.model_dump(mode="json") for e in evidence],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


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
            )
            print(_serialise(target, explorer.states, explorer.transitions,
                             explorer.evidence))
        finally:
            await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IVX GraphEngine — passive BFS explorer",
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

    args = parser.parse_args()

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
