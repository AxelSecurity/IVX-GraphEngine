"""Tests for gate-solver — CAPTCHA detection, auto-resolve, and blocking."""

from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

# Page with a Cloudflare Turnstile iframe — used by detect_captcha tests.
_GATED_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Gated</title></head>
<body>
  <h1>Protected</h1>
  <iframe id="cf-challenge"
          src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov/av0/rcv0/0x4AAAAAAADn7ROdM5XFV5/0/light/normal"
          width="300" height="65"
          style="border:0;"></iframe>
  <p>Please wait...</p>
</body>
</html>"""

# Page where JS removes the iframe after 2 seconds (simulates auto-resolve).
_AUTO_RESOLVE_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Auto-Resolve</title></head>
<body>
  <h1>Checking...</h1>
  <iframe id="cf-challenge"
          src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov/av0/rcv0/0x4AAAAAAADn7ROdM5XFV5/0/light/normal"
          width="300" height="65"
          style="border:0;"></iframe>
  <p>Verifying your browser...</p>
  <script>
    setTimeout(() => {
      const f = document.getElementById('cf-challenge');
      if (f) f.remove();
      document.querySelector('h1').textContent = 'Welcome!';
    }, 2000);
  </script>
</body>
</html>"""

# Page with a persistent captcha iframe (never auto-removes).
_PERSISTENT_GATE_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Blocked</title></head>
<body>
  <h1>Blocked</h1>
  <iframe id="cf-challenge"
          src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov/av0/rcv0/0x4AAAAAAADn7ROdM5XFV5/0/light/normal"
          width="300" height="65"
          style="border:0;"></iframe>
  <p>Complete the challenge to continue.</p>
  <!-- Also include a clickable element so we can verify it is NOT explored -->
  <button id="login-btn"
          style="position:absolute; left:480px; top:400px;
                 width:200px; height:48px; font-size:16px;">
    Proceed to dashboard
  </button>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _FixtureHandler(BaseHTTPRequestHandler):
    """Serve a single HTML page for every GET request."""

    _html: str = _PERSISTENT_GATE_PAGE

    def do_GET(self) -> None:
        body = self._html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# 1 — detect_captcha
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDetectCaptcha:
    """detect_captcha must identify known CAPTCHA providers in iframes."""

    async def test_cloudflare_turnstile_detected(self):
        """Cloudflare Turnstile iframe → returns 'cloudflare_turnstile'."""
        from playwright.async_api import async_playwright

        from graph_engine.gate_solver import detect_captcha

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_GATED_PAGE)
                import asyncio
                await asyncio.sleep(0.3)

                result = await detect_captcha(page)
                assert result == "cloudflare_turnstile", (
                    f"Expected 'cloudflare_turnstile', got {result!r}"
                )
            finally:
                await browser.close()

    async def test_no_captcha_returns_none(self):
        """Page without captcha iframe → returns None."""
        from playwright.async_api import async_playwright

        from graph_engine.gate_solver import detect_captcha

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(
                    "<html><body><p>No captcha here</p></body></html>"
                )
                import asyncio
                await asyncio.sleep(0.3)

                result = await detect_captcha(page)
                assert result is None, (
                    f"Expected None, got {result!r}"
                )
            finally:
                await browser.close()

    async def test_hcaptcha_detected(self):
        """hCaptcha iframe → returns 'hcaptcha'."""
        from playwright.async_api import async_playwright

        from graph_engine.gate_solver import detect_captcha

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(
                    '<html><body><iframe src="https://hcaptcha.com/1/api.js">'
                    '</iframe></body></html>'
                )
                import asyncio
                await asyncio.sleep(0.3)

                result = await detect_captcha(page)
                assert result == "hcaptcha", (
                    f"Expected 'hcaptcha', got {result!r}"
                )
            finally:
                await browser.close()


# ---------------------------------------------------------------------------
# 2 — try_pass_gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTryPassGate:
    """try_pass_gate — wait + checkbox, no puzzle solving."""

    async def test_auto_resolve_returns_true(self):
        """Iframe removed by JS after 2 s → try_pass_gate returns True."""
        from playwright.async_api import async_playwright

        from graph_engine.gate_solver import try_pass_gate

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_AUTO_RESOLVE_PAGE)
                import asyncio
                await asyncio.sleep(0.1)

                # Wait long enough for the 2 s JS timer to fire.
                result = await try_pass_gate(page, wait_seconds=5)
                assert result is True, (
                    "Expected auto-resolve to pass the gate"
                )
            finally:
                await browser.close()

    async def test_persistent_gate_returns_false(self):
        """Iframe never removed → try_pass_gate returns False."""
        from playwright.async_api import async_playwright

        from graph_engine.gate_solver import try_pass_gate

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_PERSISTENT_GATE_PAGE)
                import asyncio
                await asyncio.sleep(0.1)

                # Short wait so the test doesn't take forever.
                result = await try_pass_gate(page, wait_seconds=3)
                assert result is False, (
                    "Expected persistent gate to block"
                )
            finally:
                await browser.close()


# ---------------------------------------------------------------------------
# 3 — Explorer integration: blocked_by_gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplorerBlockedByGate:
    """Explorer must detect gate, record Evidence, and skip action enumeration."""

    async def test_blocked_by_gate_evidence_recorded(self):
        """When gate persists, Evidence key='blocked_by_gate' is emitted."""
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
                        captcha_wait_s=3,
                    )

                    # Evidence with key="blocked_by_gate" must exist.
                    blocked = [
                        e for e in explorer.evidence
                        if e.key == "blocked_by_gate"
                    ]
                    assert len(blocked) >= 1, (
                        "Expected at least one 'blocked_by_gate' evidence entry, "
                        f"got {[e.key for e in explorer.evidence]}"
                    )
                    assert "cloudflare_turnstile" in blocked[0].value, (
                        f"Evidence value should mention cloudflare_turnstile, "
                        f"got: {blocked[0].value}"
                    )

                    # The "Proceed to dashboard" button must NOT have been
                    # clicked — gate blocked action enumeration.
                    click_transitions = [
                        t for t in explorer.transitions
                        if t.kind.value == "click"
                    ]
                    assert len(click_transitions) == 0, (
                        "No click transitions expected — "
                        "gate should block action enumeration"
                    )

                    # Root state is the only state — no further exploration.
                    assert len(explorer.states) == 1, (
                        f"Expected exactly 1 state (root), "
                        f"got {len(explorer.states)}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()
