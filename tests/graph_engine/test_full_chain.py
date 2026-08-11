"""Full-chain integration tests — gate, click chains, replay, and resilience.

Since credential injection (email/password/OTP) has been removed from scope,
these tests verify the core exploration loop: gate solving, click-driven
navigation across multiple depth levels, replay correctness, and error
containment.
"""

from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


# ---------------------------------------------------------------------------
# HTML fixtures — gate + click chain
# ---------------------------------------------------------------------------

# Page 1 — CAPTCHA gate (auto-resolves after 2 s) + clickable link to /step2.
_ROOT_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Sign in — Microsoft</title></head>
<body>
  <h1>Sign in</h1>
  <p id="status">Verifying your browser security…</p>
  <iframe id="cf-challenge"
          src="https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov/av0/rcv0/0x4AAAAAAADn7ROdM5XFV5/0/light/normal"
          width="300" height="65"
          style="border:0;"></iframe>
  <p style="margin-top:16px;">
    <a href="/step2" id="next-step"
       style="display:inline-block;padding:10px 24px;background:#0078d4;color:#fff;text-decoration:none;font-size:16px;">Next</a>
  </p>
  <script>
    // Auto-resolve after 2 s — simulates an "invisible" Turnstile challenge.
    setTimeout(() => {
      const f = document.getElementById('cf-challenge');
      if (f) f.remove();
      document.getElementById('status').textContent = 'Verified';
    }, 2000);
  </script>
</body>
</html>"""

# Page 2 — intermediate step with a clickable "Continue" link to /step3.
_STEP2_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Step 2</title></head>
<body>
  <h1>Step 2</h1>
  <p>Almost there.</p>
  <a href="/step3" id="continue-step"
     style="display:inline-block;padding:10px 24px;background:#0078d4;color:#fff;text-decoration:none;font-size:16px;">Continue</a>
</body>
</html>"""

# Page 3 — leaf (no further links).
_STEP3_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Done</title></head>
<body><h1>Welcome</h1><p>You have arrived.</p></body>
</html>"""


# ---------------------------------------------------------------------------
# Simple two-page fixture (for fault-injection tests)
# ---------------------------------------------------------------------------

# Root page — one clickable link to /next.
_SIMPLE_ROOT = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Simple</title></head>
<body>
  <h1>Hello</h1>
  <a href="/next" id="go-next"
     style="display:inline-block;padding:10px 24px;background:#0078d4;color:#fff;text-decoration:none;font-size:16px;">Go next</a>
</body>
</html>"""

# Target page after the click.
_SIMPLE_NEXT = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Next</title></head>
<body><h1>Next page</h1><p>You arrived.</p></body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

class _GateAndClickHandler(BaseHTTPRequestHandler):
    """Serve a 3-page gate + click chain."""

    def _serve_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.rstrip("/") or "/"
        if path == "/step2":
            self._serve_html(_STEP2_PAGE)
        elif path == "/step3":
            self._serve_html(_STEP3_PAGE)
        else:
            self._serve_html(_ROOT_PAGE)

    def do_POST(self) -> None:
        self._serve_html(_STEP3_PAGE)

    def log_message(self, format, *args):
        pass


class _SimpleTwoPageHandler(BaseHTTPRequestHandler):
    """Serve a 2-page click chain: / → /next."""

    def _serve_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.rstrip("/") or "/"
        if path == "/next":
            self._serve_html(_SIMPLE_NEXT)
        else:
            self._serve_html(_SIMPLE_ROOT)

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# 1 — Full chain: gate → click → click (linear depth 0→1→2→3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullChainGateAndClickChain:
    """End-to-end: gate → click → click → leaf, with replay.

    The explorer must traverse the full chain via gate_solved and click
    transitions, create exactly 4 states in a linear progression, and
    never trigger replay fallback.
    """

    async def test_full_chain_gate_solved_and_click_chain(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TransitionKind

        server = HTTPServer(("127.0.0.1", 0), _GateAndClickHandler)
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
                        budget=Budget(
                            max_depth=5, max_nodes=20, timeout_s=60,
                        ),
                        capture_artifacts=False,
                        top_n_actions=3,  # enable click enumeration
                        captcha_wait_s=5,
                    )

                    # ---- No credential-related Evidence ------------------
                    evidence_keys = {e.key for e in explorer.evidence}
                    assert "canary_email_submit_endpoint" not in evidence_keys, (
                        "Credential evidence must not appear"
                    )
                    assert "canary_password_submit_endpoint" not in evidence_keys, (
                        "Credential evidence must not appear"
                    )
                    assert "otp_stage_reached" not in evidence_keys, (
                        "Credential evidence must not appear"
                    )

                    # ---- Root must have exactly 1 outbound transition ----
                    root_id = next(
                        s.id for s in explorer.states if s.depth == 0
                    )
                    outbound_from_root = [
                        t for t in explorer.transitions
                        if t.from_state == root_id
                    ]
                    assert len(outbound_from_root) == 1, (
                        f"Root must have exactly 1 outbound transition "
                        f"(gate_solved), got {len(outbound_from_root)}: "
                        f"{[(t.kind.value, str(t.to_state)[:8]) for t in outbound_from_root]}"
                    )
                    assert outbound_from_root[0].kind == TransitionKind.gate_solved, (
                        f"Root's only outbound must be gate_solved, "
                        f"got {outbound_from_root[0].kind.value}"
                    )

                    # ---- gate_solved transition exists --------------------
                    gate_transitions = [
                        t for t in explorer.transitions
                        if t.kind == TransitionKind.gate_solved
                    ]
                    assert len(gate_transitions) == 1, (
                        f"Expected exactly 1 gate_solved, "
                        f"got {len(gate_transitions)}"
                    )
                    gate_t = gate_transitions[0]
                    assert gate_t.trigger is not None
                    assert gate_t.trigger.get("provider") == "cloudflare_turnstile"
                    post_gate_state_id = gate_t.to_state

                    # ---- click transitions --------------------------------
                    click_transitions = [
                        t for t in explorer.transitions
                        if t.kind == TransitionKind.click
                    ]
                    # At least 2 clicks: one from post-gate, one from step2.
                    assert len(click_transitions) >= 2, (
                        f"Expected >= 2 click transitions, "
                        f"got {len(click_transitions)}: "
                        f"{[(t.trigger.get('action_label','') if t.trigger else '') for t in click_transitions]}"
                    )

                    # ---- click chain: post-gate → step2 → step3 ----------
                    # Sort clicks by depth of their from_state.
                    state_by_id = {s.id: s for s in explorer.states}
                    clicks_by_depth = sorted(
                        click_transitions,
                        key=lambda t: state_by_id[t.from_state].depth,
                    )
                    # First click originates from post-gate state.
                    assert clicks_by_depth[0].from_state == post_gate_state_id, (
                        f"First click must originate from post-gate state "
                        f"({post_gate_state_id}), "
                        f"got from_state={clicks_by_depth[0].from_state}"
                    )
                    # Second click originates from the first click's destination.
                    assert clicks_by_depth[1].from_state == clicks_by_depth[0].to_state, (
                        f"Second click must originate from first click's "
                        f"destination ({clicks_by_depth[0].to_state}), "
                        f"got from_state={clicks_by_depth[1].from_state}"
                    )

                    # ---- Depth distribution: linear chain 0→1→2→3 ---------
                    depths = {s.depth for s in explorer.states}
                    assert 0 in depths, f"Missing depth 0: {depths}"
                    assert 1 in depths, f"Missing depth 1 (post-gate): {depths}"
                    assert 2 in depths, f"Missing depth 2 (post-click1): {depths}"
                    assert 3 in depths, f"Missing depth 3 (post-click2): {depths}"

                    # ---- Exactly 4 states in the linear chain -----------------
                    assert len(explorer.states) == 4, (
                        f"Expected exactly 4 states (root, post-gate, "
                        f"post-click1, post-click2), got {len(explorer.states)}: "
                        f"{[(s.depth, s.url.rstrip('/')[-10:]) for s in explorer.states]}"
                    )

                    # ---- Leaf state (depth 3) has no outbound transitions --
                    depth3_states = [
                        s for s in explorer.states if s.depth == 3
                    ]
                    assert len(depth3_states) == 1
                    outbound_from_leaf = [
                        t for t in explorer.transitions
                        if t.from_state == depth3_states[0].id
                    ]
                    assert len(outbound_from_leaf) == 0, (
                        f"Leaf state must have 0 outbound transitions, "
                        f"got {len(outbound_from_leaf)}: "
                        f"{[t.kind.value for t in outbound_from_leaf]}"
                    )

                    # ---- No replay fallback evidence ----------------------
                    fallback_evidence = [
                        e for e in explorer.evidence
                        if e.key == "replay_fallback_used"
                    ]
                    assert len(fallback_evidence) == 0, (
                        f"Replay fallback should not have triggered; "
                        f"got {len(fallback_evidence)} entry(s)"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 2 — Node-level failure isolation: a single broken state must not kill
#     the entire exploration.
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNodeFailureDoesNotCrashExploration:
    """A single node-level exception must be contained — no crash, Evidence
    recorded, already-discovered states preserved."""

    async def test_unhandled_error_during_replay_is_contained(self):
        """When replay raises an unexpected exception, the BFS loop records
        ``unhandled_node_error`` Evidence and continues (instead of crashing)."""
        import threading
        from http.server import HTTPServer

        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer

        server = HTTPServer(("127.0.0.1", 0), _SimpleTwoPageHandler)
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

                    # ---- inject a fault: replay explodes for any
                    #      state beyond depth 0 --------------------------
                    _original_replay = explorer._replay_to_state

                    async def _faulty_replay(page, state):
                        if state.depth > 0:
                            raise TimeoutError(
                                "Simulated page.goto timeout during replay"
                            )
                        return await _original_replay(page, state)

                    explorer._replay_to_state = _faulty_replay  # type: ignore[assignment]

                    # ---- run — must NOT raise --------------------------
                    target = await explorer.run(
                        start_url,
                        budget=Budget(
                            max_depth=3, max_nodes=10, timeout_s=60,
                        ),
                        capture_artifacts=False,
                        top_n_actions=3,
                    )

                    # ---- exploration completed normally ----------------
                    assert target is not None
                    # Root state must exist (depth 0 was processed ok).
                    root_states = [
                        s for s in explorer.states if s.depth == 0
                    ]
                    assert len(root_states) == 1, (
                        f"Expected root state to survive, "
                        f"got {len(explorer.states)} states total"
                    )

                    # ---- unhandled_node_error Evidence recorded --------
                    error_evidence = [
                        e for e in explorer.evidence
                        if e.key == "unhandled_node_error"
                    ]
                    assert len(error_evidence) >= 1, (
                        f"Expected unhandled_node_error evidence, "
                        f"got {[e.key for e in explorer.evidence]}"
                    )
                    assert "Simulated page.goto timeout" in (
                        error_evidence[0].value
                    ), (
                        f"Evidence should mention the simulated error, "
                        f"got: {error_evidence[0].value}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 3 — Replay goto fault: verify the inner try/except inside
#     ``_replay_to_state_impl`` (not the broad BFS backstop) catches a
#     ``page.goto()`` failure and records ``replay_fallback_used``.
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReplayGotoExceptionIsCaught:
    """When ``page.goto()`` itself raises inside ``_replay_to_state_impl``,
    the inner handler must record ``replay_fallback_used`` — not the
    broad ``unhandled_node_error`` backstop — and the partial graph must
    survive."""

    async def test_page_goto_failure_during_replay_records_fallback_evidence(
        self,
    ):
        import threading
        from http.server import HTTPServer

        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer

        server = HTTPServer(("127.0.0.1", 0), _SimpleTwoPageHandler)
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

                    # Patch Page.goto so the FIRST call succeeds (root
                    # navigation in _navigate_and_create_state) but every
                    # subsequent call raises TimeoutError.  The second
                    # call is the root-URL goto inside
                    # _replay_to_state_impl when the BFS loop replays the
                    # path for a depth>0 state.
                    from playwright.async_api import Page as PWPage

                    _real_goto = PWPage.goto
                    _call_count = [0]

                    async def _counted_goto(page_self, url, **kwargs):
                        _call_count[0] += 1
                        if _call_count[0] > 1:
                            raise TimeoutError(
                                "Simulated page.goto timeout during replay"
                            )
                        return await _real_goto(page_self, url, **kwargs)

                    PWPage.goto = _counted_goto  # type: ignore[method-assign]

                    try:
                        # ---- run — must NOT raise ----------------------
                        target = await explorer.run(
                            start_url,
                            budget=Budget(
                                max_depth=3, max_nodes=10, timeout_s=60,
                            ),
                            capture_artifacts=False,
                            top_n_actions=3,
                        )

                        # ---- exploration completed normally ------------
                        assert target is not None

                        # ---- partial graph survives -------------------
                        # Root state (depth 0) was created before the
                        # fault — it must still be present.
                        assert len(explorer.states) >= 1, (
                            "Expected at least root state to survive"
                        )
                        depths = {s.depth for s in explorer.states}
                        assert 0 in depths, (
                            f"Root state (depth 0) must survive, "
                            f"got depths={depths}"
                        )

                        # ---- replay_fallback_used Evidence (inner) ----
                        fallback_evidence = [
                            e for e in explorer.evidence
                            if e.key == "replay_fallback_used"
                        ]
                        assert len(fallback_evidence) >= 1, (
                            "Expected replay_fallback_used evidence "
                            "(caught by inner try/except), "
                            f"got {[e.key for e in explorer.evidence]}"
                        )
                        assert "Simulated page.goto timeout" in (
                            fallback_evidence[0].value
                        ), (
                            "Evidence should mention the simulated error, "
                            f"got: {fallback_evidence[0].value}"
                        )

                        # ---- NO unhandled_node_error ------------------
                        backstop_evidence = [
                            e for e in explorer.evidence
                            if e.key == "unhandled_node_error"
                        ]
                        assert len(backstop_evidence) == 0, (
                            "Must NOT have unhandled_node_error — "
                            "the inner try/except inside "
                            "_replay_to_state_impl must catch this "
                            "before the broad BFS backstop sees it"
                        )

                    finally:
                        PWPage.goto = _real_goto  # type: ignore[method-assign]

                finally:
                    await browser.close()
        finally:
            server.shutdown()
