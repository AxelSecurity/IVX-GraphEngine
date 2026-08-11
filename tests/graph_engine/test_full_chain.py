"""Full-chain integration test — gate → email → password → OTP stop.

Simulates a realistic AiTM phishing chain where the victim is funnelled
through a CAPTCHA gate, multi-step credential harvest, and finally an
OTP/MFA challenge — at which point the explorer must stop.
"""

from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest


# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

# Page 1 — CAPTCHA gate (auto-resolves after 2 s) + email form.
# The email field is visible alongside the gate so the explorer can detect
# it immediately after the gate is solved.  The form stays in the DOM the
# whole time — real AiTM pages don't hide the form behind the captcha;
# they show both so the victim fills in credentials while waiting.
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
  <form method="POST" action="/step2" style="margin-top:16px;">
    <input type="email" id="email" name="email"
           placeholder="Email address" autocomplete="email">
    <input type="submit" id="submit-email" value="Next">
  </form>
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

# Page 2 — password harvest.
_PASSWORD_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Enter password — Microsoft</title></head>
<body>
  <h1>Enter password</h1>
  <form method="POST" action="/step3">
    <input type="password" id="password" name="password"
           placeholder="Password" autocomplete="current-password">
    <input type="submit" id="submit-password" value="Sign in">
  </form>
</body>
</html>"""

# Page 3 — OTP / MFA challenge (strong live-attack signal → stop).
_OTP_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Verify your identity — Microsoft</title></head>
<body>
  <h1>Verify your identity</h1>
  <p>Enter the code from your authenticator app.</p>
  <form method="POST" action="/done">
    <input type="text" id="otp" name="code"
           placeholder="Verification code" autocomplete="one-time-code"
           maxlength="6" inputmode="numeric">
    <input type="submit" id="submit-otp" value="Verify">
  </form>
</body>
</html>"""

# Shown after the OTP form — the explorer should never reach this page.
_DONE_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Done</title></head>
<body><h1>Welcome</h1><p>You are logged in.</p></body>
</html>"""


# ---------------------------------------------------------------------------
# Multi-route HTTP handler
# ---------------------------------------------------------------------------

class _FullChainHandler(BaseHTTPRequestHandler):
    """Serve different pages depending on the request path."""

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
            self._serve_html(_PASSWORD_PAGE)
        elif path == "/step3":
            self._serve_html(_OTP_PAGE)
        elif path == "/done":
            self._serve_html(_DONE_PAGE)
        else:
            self._serve_html(_ROOT_PAGE)

    def do_POST(self) -> None:
        path = self.path.rstrip("/") or "/"
        if path == "/step2":
            self._serve_html(_PASSWORD_PAGE)
        elif path == "/step3":
            self._serve_html(_OTP_PAGE)
        elif path == "/done":
            self._serve_html(_DONE_PAGE)
        else:
            self._serve_html(_DONE_PAGE)

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullChainGateEmailPasswordOtp:
    """End-to-end: gate → email → password → OTP stop, with replay.

    The explorer must traverse the full AiTM chain, record all expected
    Evidence, create the correct Transitions, and stop at the OTP stage
    without submitting anything.
    """

    async def test_full_chain_all_steps_and_stop_at_otp(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TransitionKind

        server = HTTPServer(("127.0.0.1", 0), _FullChainHandler)
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
                        top_n_actions=0,  # no click enumeration — form only
                        captcha_wait_s=5,
                    )

                    # ---- Evidence keys -----------------------------------
                    evidence_keys = {e.key for e in explorer.evidence}
                    assert "canary_email_submit_endpoint" in evidence_keys, (
                        f"Missing canary_email_submit_endpoint in {evidence_keys}"
                    )
                    assert "canary_password_submit_endpoint" in evidence_keys, (
                        f"Missing canary_password_submit_endpoint in {evidence_keys}"
                    )
                    assert "otp_stage_reached" in evidence_keys, (
                        f"Missing otp_stage_reached in {evidence_keys}"
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

                    # ---- form_submit transitions --------------------------
                    form_transitions = [
                        t for t in explorer.transitions
                        if t.kind == TransitionKind.form_submit
                    ]
                    assert len(form_transitions) >= 2, (
                        f"Expected >= 2 form_submit transitions, "
                        f"got {len(form_transitions)}"
                    )
                    field_kinds = {
                        t.trigger.get("field_kind") for t in form_transitions
                        if t.trigger
                    }
                    assert field_kinds >= {"email", "password"}, (
                        f"Expected {{email, password}}, got {field_kinds}"
                    )

                    # ---- email form_submit must originate from post-gate state -
                    email_transitions = [
                        t for t in form_transitions
                        if t.trigger and t.trigger.get("field_kind") == "email"
                    ]
                    assert len(email_transitions) >= 1
                    email_t = email_transitions[0]
                    assert email_t.from_state == post_gate_state_id, (
                        f"form_submit(email).from_state must be "
                        f"post-gate state ({post_gate_state_id}), "
                        f"got {email_t.from_state}"
                    )

                    # ---- password form_submit must originate from email-dest ---
                    password_transitions = [
                        t for t in form_transitions
                        if t.trigger and t.trigger.get("field_kind") == "password"
                    ]
                    assert len(password_transitions) >= 1
                    password_t = password_transitions[0]
                    assert password_t.from_state == email_t.to_state, (
                        f"form_submit(password).from_state must be "
                        f"post-email state ({email_t.to_state}), "
                        f"got {password_t.from_state}"
                    )

                    # ---- Depth distribution: linear chain 0→1→2→3 ---------
                    depths = {s.depth for s in explorer.states}
                    assert 0 in depths, f"Missing depth 0: {depths}"
                    assert 1 in depths, (
                        f"Missing depth 1 (post-gate): {depths}"
                    )
                    assert 2 in depths, (
                        f"Missing depth 2 (post-email): {depths}"
                    )
                    assert 3 in depths, (
                        f"Missing depth 3 (post-password, OTP stage): {depths}"
                    )

                    # ---- Exactly 4 states in the linear chain -----------------
                    assert len(explorer.states) == 4, (
                        f"Expected exactly 4 states (root, post-gate, "
                        f"post-email, OTP), got {len(explorer.states)}: "
                        f"{[(s.depth, s.url) for s in explorer.states]}"
                    )

                    # ---- OTP is the last state — no further transitions ---
                    otp_state_ids = {
                        e.scope_id for e in explorer.evidence
                        if e.key == "otp_stage_reached"
                    }
                    assert len(otp_state_ids) == 1, (
                        f"Expected exactly 1 OTP evidence, "
                        f"got {len(otp_state_ids)}"
                    )
                    otp_state_id = next(iter(otp_state_ids))
                    # No transition originates from the OTP state.
                    outbound_from_otp = [
                        t for t in explorer.transitions
                        if t.from_state == otp_state_id
                    ]
                    assert len(outbound_from_otp) == 0, (
                        f"Expected 0 transitions from OTP state, "
                        f"got {len(outbound_from_otp)}: "
                        f"{[t.kind.value for t in outbound_from_otp]}"
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
