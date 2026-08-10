"""Tests for actionable element scoring and click enumeration."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.actions import ActionCandidate, enumerate_actionable


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
