"""Benchmark di L4 (explorer) su URL reali — strumento manuale, non un test.

Esegue SOLO l'esplorazione L4 (profilo browser di default, niente
artefatti, niente L2/L3/L5) su ogni URL di un file e scrive un JSON con,
per URL: tempo, numero di stati e transizioni, insieme dei dom_hash,
tipi di transizione ed evidenze di errore.  Due JSON (prima/dopo una
modifica) si confrontano con ``--compare``.

Uso::

    # lista: un URL per riga, righe vuote e # ignorate
    python scripts/bench_l4.py run benchmarks/urls.txt -o benchmarks/before.json
    python scripts/bench_l4.py run benchmarks/urls.txt -o benchmarks/after.json
    python scripts/bench_l4.py compare benchmarks/before.json benchmarks/after.json

La lista contiene URL di phishing reali: resta in ``benchmarks/``
(ignorata da git) e va eseguita da una macchina/rete adatta all'analisi.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from graph_engine.budget import Budget  # noqa: E402
from graph_engine.explorer import StateGraphExplorer  # noqa: E402


def _read_urls(path: str) -> list[str]:
    urls = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


async def _explore(browser, url: str, args) -> dict:
    explorer = StateGraphExplorer(browser)
    started = time.monotonic()
    error = None
    try:
        await asyncio.wait_for(
            explorer.run(
                url,
                budget=Budget(
                    max_depth=args.max_depth,
                    max_nodes=args.max_nodes,
                    timeout_s=args.timeout,
                ),
                capture_artifacts=False,
                top_n_actions=args.top_n,
                captcha_wait_s=8,
            ),
            timeout=args.timeout + 120,
        )
    except Exception as exc:  # noqa: BLE001 — il benchmark registra e prosegue
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    return {
        "url": url,
        "seconds": round(elapsed, 2),
        "states": len(explorer.states),
        "transitions": len(explorer.transitions),
        "dom_hashes": sorted({s.dom_hash for s in explorer.states}),
        "transition_kinds": dict(Counter(
            t.kind.value if hasattr(t.kind, "value") else str(t.kind)
            for t in explorer.transitions
        )),
        "error_evidence": sorted({
            e.key for e in explorer.evidence
            if e.key in ("navigation_error", "unhandled_node_error",
                         "replay_fallback_used", "blocked_by_gate")
        }),
        "exception": error,
    }


async def _run(args) -> None:
    from playwright.async_api import async_playwright

    urls = _read_urls(args.urls)
    results = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            for i, url in enumerate(urls, 1):
                res = await _explore(browser, url, args)
                results.append(res)
                print(f"[{i}/{len(urls)}] {res['seconds']:6.1f}s "
                      f"{res['states']:3d} stati  {url}", file=sys.stderr)
        finally:
            await browser.close()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(results, indent=2) + "\n")
    secs = [r["seconds"] for r in results]
    print(json.dumps(_summary(secs), indent=2))


def _summary(secs: list[float]) -> dict:
    if not secs:
        return {}
    ordered = sorted(secs)
    return {
        "urls": len(secs),
        "total_s": round(sum(secs), 1),
        "mean_s": round(statistics.mean(secs), 2),
        "median_s": round(statistics.median(secs), 2),
        "p90_s": round(ordered[min(len(ordered) - 1, int(0.9 * len(ordered)))], 2),
    }


def _compare(args) -> None:
    before = {r["url"]: r for r in json.loads(Path(args.before).read_text())}
    after = {r["url"]: r for r in json.loads(Path(args.after).read_text())}
    common = [u for u in before if u in after]
    print(json.dumps({
        "before": _summary([before[u]["seconds"] for u in common]),
        "after": _summary([after[u]["seconds"] for u in common]),
    }, indent=2))
    tb = sum(before[u]["seconds"] for u in common)
    ta = sum(after[u]["seconds"] for u in common)
    if tb:
        print(f"\nΔ tempo totale: {100 * (ta - tb) / tb:+.1f}%")
    print("\nDifferenze di grafo (dom_hash persi / nuovi):")
    any_diff = False
    for u in common:
        lost = sorted(set(before[u]["dom_hashes"]) - set(after[u]["dom_hashes"]))
        new = sorted(set(after[u]["dom_hashes"]) - set(before[u]["dom_hashes"]))
        if lost or new:
            any_diff = True
            print(f"- {u}\n    persi: {len(lost)}  nuovi: {len(new)}  "
                  f"stati {before[u]['states']} → {after[u]['states']}")
    if not any_diff:
        print("  nessuna")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark L4 su URL reali")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("urls")
    run.add_argument("-o", "--output", required=True)
    run.add_argument("--max-depth", type=int, default=6)
    run.add_argument("--max-nodes", type=int, default=40)
    run.add_argument("--timeout", type=int, default=180)
    run.add_argument("--top-n", type=int, default=3)
    cmp_ = sub.add_parser("compare")
    cmp_.add_argument("before")
    cmp_.add_argument("after")
    args = parser.parse_args()
    if args.cmd == "run":
        asyncio.run(_run(args))
    else:
        _compare(args)


if __name__ == "__main__":
    main()
