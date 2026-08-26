"""Test per il ramo cloaking in L4: cloaking_profile → secondo albero.

Verifica che ``StateGraphExplorer.run(cloaking_profile={...})`` apra un
secondo browser context col profilo divergente rilevato da L3, colleghi
il nuovo root al root primario con una ``Transition(cloaking_probe)`` e
rispetti budget residuo, dedup e contenimento errori.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from graph_engine.budget import Budget
from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import State, TargetStatus, TransitionKind

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GOOGLEBOT_HEADERS = {"From": "googlebot@google.com", "Accept-Language": "*"}


def _make_browser():
    """Browser mock con due context distinti (primario e divergente)."""
    browser = AsyncMock()
    context1 = AsyncMock()
    page1 = AsyncMock()
    context2 = AsyncMock()
    page2 = AsyncMock()
    browser.new_context = AsyncMock(side_effect=[context1, context2])
    context1.new_page = AsyncMock(return_value=page1)
    context2.new_page = AsyncMock(return_value=page2)
    return browser, context1, page1, context2, page2


class TestCloakingProbeBranch:
    """Comportamento di _explore_cloaking_branch attraverso run()."""

    async def test_divergent_branch_creates_probe_transition(self):
        """Secondo context col profilo divergente + transizione cloaking_probe.

        Il ramo viene esplorato PRIMA del BFS primario (finestra di budget
        garantita — vedi docstring di run()).
        """
        browser, context1, page1, context2, page2 = _make_browser()

        root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="primary-root",
        )
        div_root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="divergent-root",
        )
        responses = iter([root, div_root])

        async def _fake_nav(page, url, depth):
            return next(responses)

        bfs_calls = []

        async def _fake_bfs(self_, page, context, budget, start_state,
                            max_depth_limit=None):
            bfs_calls.append((page, context, start_state, max_depth_limit))
            self_._visited.add(start_state.dom_hash)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            side_effect=_fake_nav,
        ), patch.object(
            StateGraphExplorer, "_enumerate_passive_actions",
            new_callable=AsyncMock, return_value=[],
        ), patch.object(
            StateGraphExplorer, "_bfs_loop", new=_fake_bfs,
        ):
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                "https://example.com",
                captcha_wait_s=0,
                top_n_actions=0,
                cloaking_profile={
                    "user_agent": GOOGLEBOT_UA,
                    "headers": GOOGLEBOT_HEADERS,
                },
            )

        assert target.status == TargetStatus.done

        # Secondo context aperto col profilo divergente
        assert browser.new_context.call_count == 2
        second_kwargs = browser.new_context.call_args_list[1][1]
        assert second_kwargs["user_agent"] == GOOGLEBOT_UA
        assert second_kwargs["extra_http_headers"] == GOOGLEBOT_HEADERS

        # Transizione cloaking_probe: root primario → root divergente
        probes = [
            t for t in explorer.transitions
            if t.kind == TransitionKind.cloaking_probe
        ]
        assert len(probes) == 1
        assert probes[0].from_state == target.root_state_id == root.id
        assert probes[0].to_state == div_root.id

        # div_root appeso come secondo stato; root_state_id invariato
        assert [s.dom_hash for s in explorer.states] == [
            "primary-root", "divergent-root",
        ]

        # Evidenza status explored
        probe_ev = [e for e in explorer.evidence if e.key == "cloaking_probe"]
        assert len(probe_ev) == 1
        assert json.loads(probe_ev[0].value)["status"] == "explored"

        # Il ramo è il PRIMO BFS: context2, profondità ridotta min(2, max_depth)
        assert len(bfs_calls) == 2
        first_call = bfs_calls[0]
        assert first_call[0] is page2
        assert first_call[1] is context2
        assert first_call[2] is div_root
        assert first_call[3] == 2  # min(2, budget.max_depth=6)
        # Il BFS primario arriva DOPO il ramo, senza limite di profondità
        primary_call = bfs_calls[1]
        assert primary_call[0] is page1
        assert primary_call[1] is context1
        assert primary_call[2] is root
        assert primary_call[3] is None
        assert context2.close.await_count == 1

    async def test_dedup_divergent_root_creates_no_transition(self):
        """Root divergente con dom_hash già visto → nessuna transizione."""
        browser, _, _, context2, _ = _make_browser()

        root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="same-hash",
        )
        div_root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="same-hash",
        )
        responses = iter([root, div_root])

        async def _fake_nav(page, url, depth):
            return next(responses)

        async def _fake_bfs(self_, page, context, budget, start_state,
                            max_depth_limit=None):
            self_._visited.add(start_state.dom_hash)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            side_effect=_fake_nav,
        ), patch.object(
            StateGraphExplorer, "_enumerate_passive_actions",
            new_callable=AsyncMock, return_value=[],
        ), patch.object(
            StateGraphExplorer, "_bfs_loop", new=_fake_bfs,
        ):
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                "https://example.com",
                captcha_wait_s=0,
                top_n_actions=0,
                cloaking_profile={
                    "user_agent": GOOGLEBOT_UA,
                    "headers": GOOGLEBOT_HEADERS,
                },
            )

        assert target.status == TargetStatus.done
        assert len(explorer.transitions) == 0
        assert len(explorer.states) == 1
        probe_ev = [e for e in explorer.evidence if e.key == "cloaking_probe"]
        assert len(probe_ev) == 1
        assert json.loads(probe_ev[0].value)["status"] == "deduped"
        # Il secondo context viene aperto ma chiuso senza BFS sul ramo
        assert context2.close.await_count == 1

    async def test_insufficient_budget_skips_branch(self):
        """Budget residuo sotto la riserva → evidenza skipped, un solo context."""
        browser, _, _, _, _ = _make_browser()

        root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="primary-root",
        )
        responses = iter([root])

        async def _fake_nav(page, url, depth):
            return next(responses)

        async def _fake_bfs(self_, page, context, budget, start_state,
                            max_depth_limit=None):
            self_._visited.add(start_state.dom_hash)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            side_effect=_fake_nav,
        ), patch.object(
            StateGraphExplorer, "_enumerate_passive_actions",
            new_callable=AsyncMock, return_value=[],
        ), patch.object(
            StateGraphExplorer, "_bfs_loop", new=_fake_bfs,
        ):
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                "https://example.com",
                budget=Budget(max_nodes=2, max_depth=6, timeout_s=60),
                captcha_wait_s=0,
                top_n_actions=0,
                cloaking_profile={
                    "user_agent": GOOGLEBOT_UA,
                    "headers": GOOGLEBOT_HEADERS,
                },
            )

        assert target.status == TargetStatus.done
        # Riserva di 2 nodi: 1 usato su max_nodes=2 → ramo saltato
        assert browser.new_context.call_count == 1
        probe_ev = [e for e in explorer.evidence if e.key == "cloaking_probe"]
        assert len(probe_ev) == 1
        value = json.loads(probe_ev[0].value)
        assert value["status"] == "skipped"
        assert value["reason"] == "budget"

    async def test_no_cloaking_profile_single_context(self):
        """Senza cloaking_profile → un solo context (regression guard)."""
        browser, _, _, _, _ = _make_browser()

        root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="primary-root",
        )
        responses = iter([root])

        async def _fake_nav(page, url, depth):
            return next(responses)

        async def _fake_bfs(self_, page, context, budget, start_state,
                            max_depth_limit=None):
            self_._visited.add(start_state.dom_hash)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            side_effect=_fake_nav,
        ), patch.object(
            StateGraphExplorer, "_enumerate_passive_actions",
            new_callable=AsyncMock, return_value=[],
        ), patch.object(
            StateGraphExplorer, "_bfs_loop", new=_fake_bfs,
        ):
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                "https://example.com",
                captcha_wait_s=0,
                top_n_actions=0,
            )

        assert target.status == TargetStatus.done
        assert browser.new_context.call_count == 1
        assert len(explorer.transitions) == 0
        probe_ev = [e for e in explorer.evidence if e.key == "cloaking_probe"]
        assert len(probe_ev) == 0

    async def test_navigation_error_records_cloaking_probe_error(self):
        """Navigazione del ramo fallita → cloaking_probe_error, status done."""
        browser, _, _, context2, _ = _make_browser()

        root = State(
            target_id=uuid.uuid4(),
            url="https://example.com",
            dom_hash="primary-root",
        )
        responses = iter([root, None])

        async def _fake_nav(page, url, depth):
            value = next(responses)
            if value is None:
                raise RuntimeError("boom divergente")
            return value

        async def _fake_bfs(self_, page, context, budget, start_state,
                            max_depth_limit=None):
            self_._visited.add(start_state.dom_hash)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            side_effect=_fake_nav,
        ), patch.object(
            StateGraphExplorer, "_enumerate_passive_actions",
            new_callable=AsyncMock, return_value=[],
        ), patch.object(
            StateGraphExplorer, "_bfs_loop", new=_fake_bfs,
        ):
            explorer = StateGraphExplorer(browser)
            target = await explorer.run(
                "https://example.com",
                captcha_wait_s=0,
                top_n_actions=0,
                cloaking_profile={
                    "user_agent": GOOGLEBOT_UA,
                    "headers": GOOGLEBOT_HEADERS,
                },
            )

        # Vincolo contenimento errori: nessun crash, target comunque done
        assert target.status == TargetStatus.done
        error_ev = [
            e for e in explorer.evidence if e.key == "cloaking_probe_error"
        ]
        assert len(error_ev) == 1
        assert "boom divergente" in error_ev[0].value
        assert len(explorer.transitions) == 0
        assert context2.close.await_count == 1
