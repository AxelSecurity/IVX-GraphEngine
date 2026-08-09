"""Tests for the BFS StateGraphExplorer — unit + optional integration."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.budget import Budget
from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import TargetStatus


# ---------------------------------------------------------------------------
# Helpers — build lightweight mocks that behave enough like Playwright
# ---------------------------------------------------------------------------


def _mock_response():
    """Return a mock Playwright Response with a non-redirected request chain."""
    resp = AsyncMock()
    req = AsyncMock()
    req.redirected_from = None
    resp.request = req
    return resp


def _mock_page(html: str = "<html></html>", url: str = "https://example.com") -> AsyncMock:
    """Return an AsyncMock Page preset with sane defaults."""
    page = AsyncMock()
    page.url = url
    page.content = AsyncMock(return_value=html)

    # Simulate the init-script intercept stash (empty by default).
    page.evaluate = AsyncMock(return_value=[])

    page.goto = AsyncMock(return_value=_mock_response())
    page.add_init_script = AsyncMock()
    page.route = AsyncMock()
    page.set_default_timeout = MagicMock()
    page.close = AsyncMock()
    return page


def _mock_browser(page: AsyncMock) -> tuple[AsyncMock, AsyncMock]:
    """Return (mock_browser, mock_context) that yield *page*."""
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.close = AsyncMock()

    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)

    return browser, context


# ---------------------------------------------------------------------------
# Budget tests
# ---------------------------------------------------------------------------


class TestBudgetEnforcement:
    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_max_nodes_stops_bfs(self, mock_sleep):
        """BFS stops after reaching max_nodes even if frontier has more."""
        page = _mock_page(
            html='<meta http-equiv="refresh" content="0; url=https://a.com">'
        )
        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        budget = Budget(max_nodes=2, max_depth=10, timeout_s=60)
        target = await explorer.run("https://example.com", budget=budget)

        assert target.status == TargetStatus.done
        # Root counts as 1, so at most 2 nodes total.
        assert len(explorer.states) <= 2

    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_max_depth_respected(self, mock_sleep):
        """States beyond max_depth are not pushed to frontier."""
        page = _mock_page(
            html='<meta http-equiv="refresh" content="0; url=https://a.com">'
        )
        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        budget = Budget(max_nodes=40, max_depth=0, timeout_s=60)
        target = await explorer.run("https://example.com", budget=budget)

        # depth=0 means root only — no children explored.
        assert len(explorer.states) == 1


# ---------------------------------------------------------------------------
# Visited / dedup
# ---------------------------------------------------------------------------


class TestVisitedDedup:
    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_duplicate_dom_hash_not_revisited(self, mock_sleep):
        """A dom_hash already in visited is never processed twice."""
        html = "<html><body>same</body></html>"
        page = _mock_page(html=html, url="https://x.com/root")
        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        # No meta-refresh → no children → only root state.
        budget = Budget(max_nodes=10, max_depth=5, timeout_s=60)
        await explorer.run("https://x.com/root", budget=budget)

        # Only the root state — no transitions.
        assert len(explorer.states) == 1
        assert len(explorer.transitions) == 0


# ---------------------------------------------------------------------------
# Meta-refresh parsing
# ---------------------------------------------------------------------------


class TestMetaRefresh:
    def test_parse_absolute_url(self):
        explorer = StateGraphExplorer(MagicMock())
        result = explorer._parse_meta_refresh(
            "0; url=https://evil.example/login", "https://base.example"
        )
        assert result == "https://evil.example/login"

    def test_parse_relative_url(self):
        explorer = StateGraphExplorer(MagicMock())
        result = explorer._parse_meta_refresh(
            "5; url=/dashboard", "https://base.example"
        )
        assert result == "https://base.example/dashboard"

    def test_parse_case_insensitive(self):
        explorer = StateGraphExplorer(MagicMock())
        result = explorer._parse_meta_refresh(
            '0; URL="https://phish.example"', "https://base.example"
        )
        assert result == "https://phish.example"

    def test_parse_no_url_returns_none(self):
        explorer = StateGraphExplorer(MagicMock())
        result = explorer._parse_meta_refresh(
            "5", "https://base.example"
        )
        assert result is None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorRecording:
    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_navigation_error_creates_evidence(self, mock_sleep):
        """When a page.goto raises, an Evidence entry is recorded."""
        page = _mock_page()
        page.goto = AsyncMock(side_effect=Exception("Connection refused"))

        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        target = await explorer.run("https://dead.example", budget=Budget())
        assert target.status == TargetStatus.error
        assert len(explorer.evidence) >= 1
        err = explorer.evidence[0]
        assert err.key == "navigation_error"
        assert "Connection refused" in err.value


# ---------------------------------------------------------------------------
# Integration (skipped by default — run with  pytest -m integration)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRealExplorer:
    async def test_httpbin_redirect_chain(self):
        """Explore httpbin.org/redirect/3 with real browser."""
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                explorer = StateGraphExplorer(browser)
                target = await explorer.run(
                    "http://httpbin.org/redirect/3",
                    budget=Budget(max_depth=3, max_nodes=10, timeout_s=60),
                )

                assert target.status == TargetStatus.done
                assert len(explorer.states) >= 1
            finally:
                await browser.close()
