"""Equivalenza del grafo L4 sul banco di prova (``l4_fixtures.py``).

Per ogni scenario l'explorer deve produrre ESATTAMENTE la firma salvata
in ``l4_golden.json``: stessi stati ``(depth, path, dom_hash)`` e stessi
conteggi per tipo di transizione.  È la rete di sicurezza delle
ottimizzazioni di L4 (attese, parallelismo, replay): più veloce sì, ma
nessuno stato perso o inventato.

Il golden si aggiorna SOLO in un commit che spiega perché il grafo
cambia (es. un caso prima perso e ora catturato).
"""

from __future__ import annotations

import json

import pytest

from tests.graph_engine.l4_fixtures import (
    GOLDEN_PATH,
    SCENARIOS,
    FixtureServer,
    run_scenario,
)

_GOLDEN = json.loads(GOLDEN_PATH.read_text())


@pytest.fixture(scope="module")
def fixture_server():
    with FixtureServer() as srv:
        yield srv


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
async def test_graph_matches_golden(scenario, fixture_server):
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            signature, _elapsed = await run_scenario(
                browser, fixture_server.base, scenario
            )
        finally:
            await browser.close()

    expected = _GOLDEN[scenario]
    assert signature["states"] == expected["states"], (
        f"{scenario}: stati diversi dal golden"
    )
    assert signature["transition_kinds"] == expected["transition_kinds"], (
        f"{scenario}: transizioni diverse dal golden"
    )


def test_golden_covers_every_scenario():
    assert set(_GOLDEN) == set(SCENARIOS)
