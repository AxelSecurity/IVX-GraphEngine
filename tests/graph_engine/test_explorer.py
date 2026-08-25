"""Tests for the BFS StateGraphExplorer — unit + optional integration."""

from __future__ import annotations

import asyncio
import http.server
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.budget import Budget
from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import TargetStatus, TransitionKind


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
# Explicit target_id
# ---------------------------------------------------------------------------


class TestExplicitTargetId:
    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_explicit_target_id_preserved(self, mock_sleep):
        """Quando target_id viene passato esplicitamente, il target
        esplorato DEVE avere quell'UUID — non uno generato internamente."""
        import uuid as _uuid

        page = _mock_page()
        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        explicit_id = _uuid.uuid4()
        target = await explorer.run(
            "https://example.com",
            budget=Budget(),
            target_id=explicit_id,
        )

        assert target.id == explicit_id
        # Anche gli stati figli devono nascere con lo stesso target_id
        for state in explorer.states:
            assert state.target_id == explicit_id

    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_no_target_id_generates_new(self, mock_sleep):
        """Se target_id NON viene passato, il target riceve un UUID
        generato internamente — comportamento invariato."""
        page = _mock_page()
        browser, _ = _mock_browser(page)
        explorer = StateGraphExplorer(browser)

        target = await explorer.run("https://example.com", budget=Budget())

        # Deve essere un UUID valido (36 caratteri, 4 trattini)
        tid = str(target.id)
        assert len(tid) == 36
        assert tid.count("-") == 4
        # Gli stati devono avere lo stesso target_id
        for state in explorer.states:
            assert state.target_id == target.id


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
# Settle polling (adaptive post-goto wait) — real browser + local server
# ---------------------------------------------------------------------------
# Questi test usano un HTTPServer locale su 127.0.0.1 (porta random) e un
# browser Chromium headless REALE: il polling del settle dipende da timing
# reali (asyncio.sleep, setTimeout del browser), quindi asyncio.sleep NON
# va mockato qui.


def _make_local_handler(start_html: str):
    """Costruisce un handler che serve *start_html* su /start e una
    pagina fissa su /payload."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/start"):
                body = start_html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
            elif self.path.startswith("/payload"):
                body = b"<html><body>payload reached</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
            else:
                body = b"not found"
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # silenzia i log del server

    return _Handler


def _delayed_redirect_html(delay_ms: int = 2000, target: str = "/payload") -> str:
    """HTML che esegue window.location.href dopo *delay_ms* millisecondi —
    replica esatta del pattern di evasione (2s) trovato su un kit TDS reale."""
    return (
        "<html><body>start page"
        "<script>setTimeout(function () {"
        f"window.location.href = {target!r};"
        f"}}, {delay_ms});</script>"
        "</body></html>"
    )


@pytest.fixture
def local_server():
    """Factory: avvia un HTTPServer locale in un thread separato e
    restituisce l'URL base. I server vengono spenti a fine test."""
    servers = []

    def _start(start_html: str) -> str:
        handler = _make_local_handler(start_html)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{port}"

    try:
        yield _start
    finally:
        for server, thread in servers:
            server.shutdown()
            thread.join()


@pytest.fixture
async def real_browser():
    """Browser Chromium headless reale, chiuso a fine test."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            await browser.close()


class TestSettlePolling:
    """Polling adattivo post-goto: redirect JS ritardati vs tetto massimo."""

    async def test_delayed_js_redirect_captured(self, real_browser, local_server):
        """Redirect setTimeout(2000ms) → transizione js_location.

        Replica il caso reale (kit TDS con delay 2s): l'attesa fissa di
        1.5s lo perdeva del tutto; il polling con tetto 4.0 lo cattura e
        produce una transizione js_location verso la destinazione reale.
        """
        base = local_server(_delayed_redirect_html(2000, "/payload"))
        explorer = StateGraphExplorer(real_browser)

        target = await explorer.run(
            base + "/start",
            budget=Budget(max_depth=2, max_nodes=10, timeout_s=60),
            capture_artifacts=False,
            top_n_actions=0,
            captcha_wait_s=0,
            settle_max_wait_s=4.0,
        )

        assert target.status == TargetStatus.done
        js_transitions = [
            t for t in explorer.transitions
            if t.kind == TransitionKind.js_location
        ]
        assert len(js_transitions) == 1, (
            f"attesa 1 transizione js_location, ottenute "
            f"{[(t.kind, t.to_state) for t in explorer.transitions]!r}"
        )
        dest_state = next(
            s for s in explorer.states
            if s.id == js_transitions[0].to_state
        )
        assert dest_state.url == base + "/payload"
        assert dest_state.depth == 1

    async def test_insufficient_settle_yields_leaf(self, real_browser, local_server):
        """Con tetto 1.0s il redirect a 2s NON viene visto → stato foglia.

        Comportamento del vecchio sleep fisso: nessuna transizione,
        il target resta un singolo stato (foglia).
        """
        base = local_server(_delayed_redirect_html(2000, "/payload"))
        explorer = StateGraphExplorer(real_browser)

        target = await explorer.run(
            base + "/start",
            budget=Budget(max_depth=2, max_nodes=10, timeout_s=60),
            capture_artifacts=False,
            top_n_actions=0,
            captcha_wait_s=0,
            settle_max_wait_s=1.0,
        )

        assert target.status == TargetStatus.done
        assert len(explorer.states) == 1
        assert len(explorer.transitions) == 0

    async def test_no_redirect_settles_early(self, real_browser, local_server):
        """Pagina senza redirect → il poll esce per quiete, NON paga il tetto.

        Con tetto 4.0 l'uscita attesa è ~2.5s (finestra minima di
        osservazione + 2 cicli quieti). Il tetto pieno costerebbe >= 4.0s:
        l'uscita anticipata deve essere verificabile sul tempo reale.
        """
        base = local_server("<html><body>static page</body></html>")
        explorer = StateGraphExplorer(real_browser)

        started = time.monotonic()
        target = await explorer.run(
            base + "/start",
            budget=Budget(max_depth=2, max_nodes=10, timeout_s=60),
            capture_artifacts=False,
            top_n_actions=0,
            captcha_wait_s=0,
            settle_max_wait_s=4.0,
        )
        elapsed = time.monotonic() - started

        assert target.status == TargetStatus.done
        assert len(explorer.states) == 1
        assert len(explorer.transitions) == 0
        # Quiete: mai prima del minimo di osservazione (1.5s + 2 cicli
        # da 0.5s), sempre molto sotto il tetto pieno (>= 4.0s).
        assert 2.0 <= elapsed < 3.5, (
            f"settle fuori dal range atteso di uscita per quiete: "
            f"{elapsed:.2f}s (atteso tra 2.0 e 3.5)"
        )


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
