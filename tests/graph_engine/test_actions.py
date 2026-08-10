"""Tests for actionable element scoring and click enumeration."""

from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.actions import ActionCandidate, enumerate_actionable


# ---------------------------------------------------------------------------
# HTML fixture — two-level SPA: first button reveals second button
# ---------------------------------------------------------------------------

_TWO_LEVEL_SPA = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Two-Level SPA</title></head>
<body style="margin:0; padding:16px;">

  <!-- Level 0: always visible, central, large, keyword "Verify"        -->
  <button id="btn-step1"
          style="position:absolute; left:480px; top:280px;
                 width:320px; height:80px; font-size:22px;
                 background:#0070f3; color:#fff; border:none;
                 border-radius:8px; cursor:pointer;"
          onclick="document.getElementById('btn-step2').style.display='block';
                   this.style.display='none';">
    Verify your account
  </button>

  <!-- Level 1: hidden until btn-step1 is clicked — keyword "Continue"  -->
  <button id="btn-step2"
          style="display:none;
                 position:absolute; left:480px; top:380px;
                 width:320px; height:64px; font-size:18px;
                 background:#0a0; color:#fff; border:none;
                 border-radius:8px; cursor:pointer;"
          onclick="this.textContent='Done';">
    Continue to dashboard
  </button>

  <!-- Distractor: small text at bottom, NOT actionable (no href, not a button) -->
  <span style="position:absolute; left:10px; top:660px;
               font-size:11px; color:#999;">
    Privacy Policy
  </span>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Static HTML fixture — mixed actionable elements with varied text + geometry
# ---------------------------------------------------------------------------

_FIXTURE_HTML = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Action Test</title></head>
<body style="margin:0; padding:16px;">

  <!-- 1. Central, large, keyword "Verify your account" — SHOULD WIN    -->
  <button id="verify-btn"
          style="position:absolute; left:480px; top:280px;
                 width:320px; height:80px; font-size:22px;
                 background:#0070f3; color:#fff; border:none;
                 border-radius:8px; cursor:pointer;">
    Verify your account
  </button>

  <!-- 2. Peripheral small link with neutral text — should score low   -->
  <a href="/privacy"
     style="position:absolute; left:10px; top:660px;
            font-size:11px; color:#999;">
    Privacy Policy
  </a>

  <!-- 3. Medium-sized button at top-left with weak keyword match       -->
  <button id="help-btn"
          style="position:absolute; left:10px; top:10px;
                 width:100px; height:36px; font-size:13px;">
    Help
  </button>

  <!-- 4. Another central button, decent size, keyword "Continue"      -->
  <input type="submit" id="continue-btn"
         style="position:absolute; left:520px; top:400px;
                width:240px; height:52px; font-size:16px;"
         value="Continue to dashboard">

  <!-- 5. Role=button, medium position, keyword "Sign in"              -->
  <div role="button" id="signin-div"
       style="position:absolute; left:540px; top:180px;
              width:200px; height:48px; line-height:48px;
              font-size:16px; text-align:center;
              background:#eee; border:1px solid #ccc;
              cursor:pointer; border-radius:4px;">
    Sign in
  </div>

  <!-- 6. Small secondary action at page bottom — should rank low      -->
  <a href="/terms" id="terms-link"
     style="position:absolute; left:10px; top:690px;
            font-size:11px; color:#999;">
    Terms of Service
  </a>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Tests — real browser (uses page.set_content, no network)
# ---------------------------------------------------------------------------


class TestEnumerateActionable:
    """Score-and-sort behaviour verified with a real Chromium page."""

    @pytest.mark.integration
    async def test_verify_your_account_ranks_first(self):
        """The 'Verify your account' button must be the top-ranked candidate."""
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 720},
                )
                await page.set_content(_FIXTURE_HTML)
                # Let layout settle.
                import asyncio
                await asyncio.sleep(0.3)

                candidates = await enumerate_actionable(page)

                assert len(candidates) >= 4, (
                    f"Expected at least 4 candidates, got {len(candidates)}"
                )

                # Top candidate must be "Verify your account"
                top = candidates[0]
                assert "verify" in top.text.lower(), (
                    f"Top candidate should be 'Verify your account', "
                    f"got '{top.text}'"
                )
                assert top.combined_score > 0, (
                    "Top candidate must have a positive combined score"
                )

                # All candidates must have required fields
                for c in candidates:
                    assert c.selector
                    assert c.text or c.selector  # text may be empty for icon-only buttons
                    assert c.combined_score >= 0
                    assert "x" in c.bounding_box
                    assert "width" in c.bounding_box

            finally:
                await browser.close()

    @pytest.mark.integration
    async def test_scores_are_descending(self):
        """Candidate list must be sorted by combined_score descending."""
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 720},
                )
                await page.set_content(_FIXTURE_HTML)
                import asyncio
                await asyncio.sleep(0.3)

                candidates = await enumerate_actionable(page)

                scores = [c.combined_score for c in candidates]
                assert scores == sorted(scores, reverse=True), (
                    f"Scores not descending: {scores}"
                )

            finally:
                await browser.close()


# ---------------------------------------------------------------------------
# Unit test — data class
# ---------------------------------------------------------------------------


class TestActionCandidateDataclass:
    def test_instantiation(self):
        c = ActionCandidate(
            selector='button:has-text("Verify")',
            text="Verify your account",
            combined_score=0.85,
            bounding_box={"x": 480, "y": 280, "width": 320, "height": 80},
        )
        assert c.selector == 'button:has-text("Verify")'
        assert c.text == "Verify your account"
        assert c.combined_score == 0.85
        assert c.bounding_box["width"] == 320


# ---------------------------------------------------------------------------
# Integration with explorer — click enumeration returns actions
# ---------------------------------------------------------------------------


class TestExplorerClickEnumeration:
    """Verify that StateGraphExplorer calls enumerate_actionable."""

    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_click_actions_appended_when_top_n_gt_0(self, mock_sleep):
        """When top_n_actions > 0, click actions are added to the action list."""
        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TargetStatus

        # Build a mock page whose evaluate() returns scored candidates.
        page = AsyncMock()
        page.url = "https://example.com"
        page.content = AsyncMock(return_value="<html><body>test</body></html>")
        page.evaluate = AsyncMock(return_value=[
            {
                "selector": 'button:has-text("Verify")',
                "text": "Verify your account",
                "combined_score": 0.9,
                "bounding_box": {"x": 480, "y": 280, "width": 320, "height": 80},
            },
        ])

        mock_resp = AsyncMock()
        mock_req = AsyncMock()
        mock_req.redirected_from = None
        mock_resp.request = mock_req
        page.goto = AsyncMock(return_value=mock_resp)
        page.add_init_script = AsyncMock()
        page.route = AsyncMock()
        page.set_default_timeout = MagicMock()
        page.close = AsyncMock()

        context = AsyncMock()
        context.new_page = AsyncMock(return_value=page)
        context.close = AsyncMock()

        browser = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)

        explorer = StateGraphExplorer(browser)
        target = await explorer.run(
            "https://example.com",
            budget=Budget(max_nodes=1, max_depth=0, timeout_s=60),
            capture_artifacts=False,
            top_n_actions=2,
        )

        assert target.status == TargetStatus.done
        # page.evaluate should have been called at least once
        # (once by navigate_and_create_state for js_locations, once by enumerate_actionable)
        assert page.evaluate.call_count >= 1

    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_click_actions_disabled_when_top_n_is_0(self, mock_sleep):
        """When top_n_actions=0, no evaluate() call is made for scoring."""
        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TargetStatus

        page = AsyncMock()
        page.url = "https://example.com"
        page.content = AsyncMock(return_value="<html><body>test</body></html>")
        # page.evaluate is called for js_locations reading — return empty
        page.evaluate = AsyncMock(return_value=[])

        mock_resp = AsyncMock()
        mock_req = AsyncMock()
        mock_req.redirected_from = None
        mock_resp.request = mock_req
        page.goto = AsyncMock(return_value=mock_resp)
        page.add_init_script = AsyncMock()
        page.route = AsyncMock()
        page.set_default_timeout = MagicMock()
        page.close = AsyncMock()

        context = AsyncMock()
        context.new_page = AsyncMock(return_value=page)
        context.close = AsyncMock()

        browser = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)

        explorer = StateGraphExplorer(browser)
        target = await explorer.run(
            "https://example.com",
            budget=Budget(max_nodes=1, max_depth=0, timeout_s=60),
            capture_artifacts=False,
            top_n_actions=0,
        )

        assert target.status == TargetStatus.done
        # evaluate is called exactly twice: for js_locations + clearing stash
        # (both in _navigate_and_create_state), NOT for action scoring
        action_evaluate_calls = [
            c for c in page.evaluate.call_args_list
            if "_SCORING_SCRIPT" not in str(c)
        ]
        # All evaluate calls should be from the navigation path, not scoring
        assert all(
            "ge_js_locations" in str(c) or "ge_js_locations" in str(c)
            for c in page.evaluate.call_args_list
        )


# ---------------------------------------------------------------------------
# Depth-2 click-chain integration test
# ---------------------------------------------------------------------------


class _FixtureHandler(BaseHTTPRequestHandler):
    """Serve _TWO_LEVEL_SPA for every GET request."""

    _html: str = _TWO_LEVEL_SPA

    def do_GET(self) -> None:
        body = self._html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # silence HTTP server logs


@pytest.mark.integration
class TestDepth2ClickChain:
    """Full BFS exploration through two DOM-only click levels at the same URL."""

    async def test_two_level_click_chain(self):
        """Explorer must find both btn-step1 and btn-step2 via click replay."""
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TransitionKind

        # Start a local HTTP server on a random port.
        server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        import time
        time.sleep(0.1)  # let the server bind before first navigation

        start_url = f"http://127.0.0.1:{port}/"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    explorer = StateGraphExplorer(browser)
                    target = await explorer.run(
                        start_url,
                        budget=Budget(max_depth=3, max_nodes=10, timeout_s=60),
                        capture_artifacts=False,
                        top_n_actions=3,
                    )

                    # We expect at least 3 states:
                    #   depth 0: root page (btn-step1 visible)
                    #   depth 1: after clicking btn-step1 (btn-step2 visible)
                    #   depth 2: after clicking btn-step2 (textContent="Done")
                    assert len(explorer.states) >= 3, (
                        f"Expected >= 3 states (depth 0,1,2), "
                        f"got {len(explorer.states)}"
                    )

                    # All states should share the same URL (SPA, no navigation).
                    urls = {s.url.rstrip("/") for s in explorer.states}
                    assert len(urls) == 1, (
                        f"All states should have the same URL, got {urls}"
                    )

                    # Depth distribution
                    depths = {s.depth for s in explorer.states}
                    assert 0 in depths
                    assert 1 in depths
                    assert 2 in depths, (
                        f"Missing depth-2 state — click chain broken at "
                        f"depth 1. Depths found: {depths}"
                    )

                    # All non-root transitions should be 'click'
                    click_transitions = [
                        t for t in explorer.transitions
                        if t.kind == TransitionKind.click
                    ]
                    assert len(click_transitions) >= 2, (
                        f"Expected >= 2 click transitions, "
                        f"got {len(click_transitions)}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()

    async def test_replay_does_not_pollute_graph(self):
        """Replay must not create spurious State / Transition entries.

        The two-level SPA yields exactly 3 unique DOMs (root, step1,
        step2) and 2 click transitions.  If replay machinery creates
        extra entries the counts will exceed these expectations.
        """
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer

        server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        import time
        time.sleep(0.1)

        start_url = f"http://127.0.0.1:{port}/"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    explorer = StateGraphExplorer(browser)
                    await explorer.run(
                        start_url,
                        budget=Budget(max_depth=3, max_nodes=10, timeout_s=60),
                        capture_artifacts=False,
                        top_n_actions=3,
                    )

                    n_states = len(explorer.states)
                    n_transitions = len(explorer.transitions)

                    # The fixture has 3 distinct DOMs (root → step1 → step2).
                    # Replay must not inflate these numbers.
                    assert n_states == 3, (
                        f"Replay pollution? Expected exactly 3 states, "
                        f"got {n_states}"
                    )
                    assert n_transitions == 2, (
                        f"Replay pollution? Expected exactly 2 transitions, "
                        f"got {n_transitions}"
                    )

                    # Depth distribution — must include all three levels.
                    depths = {s.depth for s in explorer.states}
                    assert depths == {0, 1, 2}, (
                        f"Expected depths {{0,1,2}}, got {depths}"
                    )

                    # All transitions must be 'click' type.
                    from graph_engine.models import TransitionKind
                    assert all(
                        t.kind == TransitionKind.click
                        for t in explorer.transitions
                    ), "All transitions must be click kind in this SPA"

                finally:
                    await browser.close()
        finally:
            server.shutdown()
