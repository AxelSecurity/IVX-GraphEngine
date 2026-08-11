"""Tests for credential injection — field detection, submit, OTP stop."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

import pytest


# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

# Page with only an email field + submit button.
_EMAIL_ONLY_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Email</title></head>
<body>
  <h1>Sign in</h1>
  <form method="POST" action="/step2">
    <input type="email" id="email" name="email"
           placeholder="Enter your email" autocomplete="email">
    <input type="submit" id="submit-btn" value="Next">
  </form>
</body>
</html>"""

# Step-2 page after email — password field.
_PASSWORD_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Password</title></head>
<body>
  <h1>Enter password</h1>
  <form method="POST" action="/done">
    <input type="password" id="password" name="password"
           placeholder="Password" autocomplete="current-password">
    <input type="submit" id="submit-btn" value="Sign in">
  </form>
</body>
</html>"""

# Password page WITH an OTP field on the same page — explorer must stop.
_PASSWORD_WITH_OTP_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Password + OTP</title></head>
<body>
  <h1>Enter password</h1>
  <form method="POST" action="/done">
    <input type="password" id="password" name="password"
           placeholder="Password" autocomplete="current-password">
    <input type="text" id="otp" name="code"
           placeholder="Verification code" autocomplete="one-time-code"
           maxlength="6">
    <input type="submit" id="submit-btn" value="Verify">
  </form>
</body>
</html>"""

# Done page — shown after successful submit.
_DONE_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Done</title></head>
<body>
  <h1>Welcome</h1>
  <p>You are logged in.</p>
</body>
</html>"""

# Form that submits to a known IdP domain.
_IDP_FORM_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>IdP</title></head>
<body>
  <h1>Microsoft Sign-in</h1>
  <form method="POST" action="https://login.microsoftonline.com/common/login">
    <input type="email" id="email" name="email"
           placeholder="Email address" autocomplete="email">
    <input type="submit" id="submit-btn" value="Next">
  </form>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Multi-route HTTP handler
# ---------------------------------------------------------------------------

class _MultiRouteHandler(BaseHTTPRequestHandler):
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
        elif path == "/done":
            self._serve_html(_DONE_PAGE)
        else:
            self._serve_html(_EMAIL_ONLY_PAGE)

    def do_POST(self) -> None:
        path = self.path.rstrip("/") or "/"
        if path == "/step2":
            self._serve_html(_PASSWORD_PAGE)
        elif path == "/done":
            self._serve_html(_DONE_PAGE)
        else:
            self._serve_html(_DONE_PAGE, status=302)

    def log_message(self, format, *args):
        pass


class _PasswordWithOtpHandler(BaseHTTPRequestHandler):
    """Serve the password+OTP page for every request."""

    def do_GET(self) -> None:
        body = _PASSWORD_WITH_OTP_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = _DONE_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _IdpFormHandler(BaseHTTPRequestHandler):
    """Serve the IdP-targeting form page."""

    def do_GET(self) -> None:
        body = _IDP_FORM_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# 1 — Email-only form
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEmailOnlyForm:
    """Single email field → submit → form_submit transition + evidence."""

    async def test_email_submit_creates_evidence_and_transition(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TransitionKind

        server = HTTPServer(("127.0.0.1", 0), _MultiRouteHandler)
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
                            max_depth=3, max_nodes=10, timeout_s=60,
                        ),
                        capture_artifacts=False,
                        top_n_actions=0,
                    )

                    # ---- evidence: canary_email_submit_endpoint ---------
                    email_evidence = [
                        e for e in explorer.evidence
                        if e.key == "canary_email_submit_endpoint"
                    ]
                    assert len(email_evidence) >= 1, (
                        f"Expected canary_email_submit_endpoint evidence, "
                        f"got {[e.key for e in explorer.evidence]}"
                    )
                    ev = json.loads(email_evidence[0].value)
                    assert ev.get("field_kind") == "email"

                    # ---- transition: form_submit ------------------------
                    form_transitions = [
                        t for t in explorer.transitions
                        if t.kind == TransitionKind.form_submit
                    ]
                    assert len(form_transitions) >= 1, (
                        "Expected at least one form_submit transition"
                    )
                    assert form_transitions[0].trigger is not None
                    assert form_transitions[0].trigger.get(
                        "field_kind"
                    ) == "email"

                    # ---- at least 2 states: root + post-submit ----------
                    assert len(explorer.states) >= 2, (
                        f"Expected >= 2 states (root + post-submit), "
                        f"got {len(explorer.states)}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 2 — Two-step: email → password
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTwoStepEmailPassword:
    """Email page → submit → password page → submit → done."""

    async def test_two_step_reaches_password_depth(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer
        from graph_engine.models import TransitionKind

        server = HTTPServer(("127.0.0.1", 0), _MultiRouteHandler)
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
                        top_n_actions=0,
                    )

                    # ---- both evidence keys present ---------------------
                    evidence_keys = {e.key for e in explorer.evidence}
                    assert "canary_email_submit_endpoint" in evidence_keys, (
                        f"Missing canary_email_submit_endpoint in {evidence_keys}"
                    )
                    assert "canary_password_submit_endpoint" in evidence_keys, (
                        f"Missing canary_password_submit_endpoint in {evidence_keys}"
                    )

                    # ---- two form_submit transitions -------------------
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
                    assert field_kinds == {"email", "password"}, (
                        f"Expected {{email, password}}, got {field_kinds}"
                    )

                    # ---- depth distribution -----------------------------
                    depths = {s.depth for s in explorer.states}
                    assert 0 in depths
                    assert 1 in depths, (
                        f"Missing depth 1 (post-email), depths={depths}"
                    )
                    assert 2 in depths, (
                        f"Missing depth 2 (post-password), depths={depths}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 3 — OTP after password → explorer must stop
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOtpStopCondition:
    """When an OTP field is on the page, explorer must stop immediately."""

    async def test_otp_detected_stops_exploration(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer

        server = HTTPServer(("127.0.0.1", 0), _PasswordWithOtpHandler)
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
                            max_depth=3, max_nodes=10, timeout_s=60,
                        ),
                        capture_artifacts=False,
                        top_n_actions=0,
                    )

                    # ---- evidence: otp_stage_reached -------------------
                    otp_evidence = [
                        e for e in explorer.evidence
                        if e.key == "otp_stage_reached"
                    ]
                    assert len(otp_evidence) >= 1, (
                        f"Expected otp_stage_reached evidence, "
                        f"got {[e.key for e in explorer.evidence]}"
                    )

                    # ---- NO password submit evidence -------------------
                    password_evidence = [
                        e for e in explorer.evidence
                        if e.key == "canary_password_submit_endpoint"
                    ]
                    assert len(password_evidence) == 0, (
                        "Password should NOT have been submitted — "
                        "OTP detection must stop exploration first"
                    )

                    # ---- only root state (OTP blocked exploration) -----
                    assert len(explorer.states) == 1, (
                        f"Expected exactly 1 state (root), "
                        f"got {len(explorer.states)}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 4 — Known IdP endpoint detection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestKnownIdpDetection:
    """Form submitting to a known IdP domain records the match."""

    async def test_idp_match_evidence_recorded(self):
        from playwright.async_api import async_playwright

        from graph_engine.budget import Budget
        from graph_engine.explorer import StateGraphExplorer

        server = HTTPServer(("127.0.0.1", 0), _IdpFormHandler)
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
                            max_depth=3, max_nodes=10, timeout_s=60,
                        ),
                        capture_artifacts=False,
                        top_n_actions=0,
                    )

                    # ---- evidence: canary_email_submit_endpoint --------
                    email_evidence = [
                        e for e in explorer.evidence
                        if e.key == "canary_email_submit_endpoint"
                    ]
                    assert len(email_evidence) >= 1, (
                        "Expected canary_email_submit_endpoint evidence"
                    )

                    # ---- evidence: target_matches_known_idp ------------
                    idp_evidence = [
                        e for e in explorer.evidence
                        if e.key == "target_matches_known_idp"
                    ]
                    assert len(idp_evidence) >= 1, (
                        f"Expected target_matches_known_idp evidence, "
                        f"got {[e.key for e in explorer.evidence]}"
                    )
                    assert "login.microsoftonline.com" in (
                        idp_evidence[0].value
                    ), (
                        f"Expected 'login.microsoftonline.com' in IdP evidence, "
                        f"got: {idp_evidence[0].value}"
                    )

                finally:
                    await browser.close()
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# 5 — OTP detection precision: regression + positive split-box test
# ---------------------------------------------------------------------------

# Regression fixture: phone field with "OTP" in surrounding helper text,
# but no actual OTP field anywhere on the page.
_PHONE_WITH_OTP_HELPER_TEXT = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Verify phone</title></head>
<body>
  <h1>Verify your phone number</h1>
  <form method="POST" action="/verify">
    <label for="phone">Phone number</label>
    <input type="tel" id="phone" name="phone"
           placeholder="+39 123 456 7890" autocomplete="tel">
    <small>We will send you an OTP verification code to confirm your identity.</small>
    <button type="submit" id="send-code">Send code</button>
  </form>
</body>
</html>"""

# Positive fixture: 4 split OTP digit boxes (real OTP pattern).
_OTP_SPLIT_BOXES_PAGE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Verify OTP</title></head>
<body>
  <h1>Enter verification code</h1>
  <p>We sent a 4-digit code to your phone.</p>
  <form method="POST" action="/verify-otp">
    <div class="otp-digits">
      <input type="text" maxlength="1" inputmode="numeric" class="otp-digit"
             name="digit1" id="digit1" aria-label="Digit 1 of 4">
      <input type="text" maxlength="1" inputmode="numeric" class="otp-digit"
             name="digit2" id="digit2" aria-label="Digit 2 of 4">
      <input type="text" maxlength="1" inputmode="numeric" class="otp-digit"
             name="digit3" id="digit3" aria-label="Digit 3 of 4">
      <input type="text" maxlength="1" inputmode="numeric" class="otp-digit"
             name="digit4" id="digit4" aria-label="Digit 4 of 4">
    </div>
    <button type="submit" id="verify-btn">Verify</button>
  </form>
</body>
</html>"""

# Scattered-inputs fixture: 3 maxlength=1 inputs in unrelated sections
# of a long form — they do NOT share a parent or grandparent, so the
# proximity check must prevent a false positive.
_SCATTERED_SINGLE_CHAR_FIELDS = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Long form</title></head>
<body>
  <h1>Registration</h1>
  <form method="POST" action="/register">
    <fieldset>
      <legend>Personal info</legend>
      <label>Middle initial:
        <input type="text" maxlength="1" name="initial" id="initial"
               placeholder="M">
      </label>
    </fieldset>
    <fieldset>
      <legend>Address</legend>
      <label>Floor:
        <input type="text" maxlength="1" name="floor" id="floor"
               placeholder="3">
      </label>
    </fieldset>
    <fieldset>
      <legend>Preferences</legend>
      <label>Favourite letter:
        <input type="text" maxlength="1" name="letter" id="letter"
               placeholder="A">
      </label>
    </fieldset>
    <button type="submit">Register</button>
  </form>
</body>
</html>"""


class _SinglePageHandler(BaseHTTPRequestHandler):
    """Serve a fixed HTML page for every request."""

    page_html: str = ""

    def do_GET(self) -> None:
        body = self.page_html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = self.page_html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestOtpDetectionPrecision:
    """OTP detection must NOT fire on surrounding text — only on the
    input's own attributes.  Split OTP digit boxes (maxlength=1, >=3)
    must fire correctly."""

    async def test_phone_with_otp_helper_text_does_not_trigger(self):
        """Regression: a phone field with 'OTP' in nearby helper text
        must NOT trigger OTP detection."""
        from playwright.async_api import async_playwright

        from graph_engine.credential_injection import detect_otp_field

        # Bind the fixture to the handler class.
        _SinglePageHandler.page_html = _PHONE_WITH_OTP_HELPER_TEXT

        server = HTTPServer(("127.0.0.1", 0), _SinglePageHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        import time
        time.sleep(0.1)

        url = f"http://127.0.0.1:{port}/"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    await page.goto(url, wait_until="domcontentloaded")
                    await page.wait_for_timeout(500)

                    result = await detect_otp_field(page)
                    assert result is False, (
                        f"OTP detection must NOT fire on phone field "
                        f"with 'OTP' in surrounding helper text, "
                        f"got {result!r}"
                    )
                finally:
                    await browser.close()
        finally:
            server.shutdown()

    async def test_split_otp_digit_boxes_trigger_correctly(self):
        """Positive: 4 separate maxlength=1 inputs (split OTP boxes)
        must trigger OTP detection via pattern B."""
        from playwright.async_api import async_playwright

        from graph_engine.credential_injection import detect_otp_field

        _SinglePageHandler.page_html = _OTP_SPLIT_BOXES_PAGE

        server = HTTPServer(("127.0.0.1", 0), _SinglePageHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        import time
        time.sleep(0.1)

        url = f"http://127.0.0.1:{port}/"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    await page.goto(url, wait_until="domcontentloaded")
                    await page.wait_for_timeout(500)

                    result = await detect_otp_field(page)
                    assert result is True, (
                        f"OTP detection MUST fire on 4 split "
                        f"maxlength=1 digit boxes, got {result!r}"
                    )
                finally:
                    await browser.close()
        finally:
            server.shutdown()

    async def test_scattered_single_char_fields_do_not_trigger(self):
        """Regression: 3 maxlength=1 inputs in unrelated form sections
        (different parents AND grandparents) must NOT trigger OTP
        detection — the proximity check must prevent it."""
        from playwright.async_api import async_playwright

        from graph_engine.credential_injection import detect_otp_field

        _SinglePageHandler.page_html = _SCATTERED_SINGLE_CHAR_FIELDS

        server = HTTPServer(("127.0.0.1", 0), _SinglePageHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        import time
        time.sleep(0.1)

        url = f"http://127.0.0.1:{port}/"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page()
                    await page.goto(url, wait_until="domcontentloaded")
                    await page.wait_for_timeout(500)

                    result = await detect_otp_field(page)
                    assert result is False, (
                        f"OTP detection must NOT fire on scattered "
                        f"maxlength=1 fields in unrelated sections, "
                        f"got {result!r}"
                    )
                finally:
                    await browser.close()
        finally:
            server.shutdown()
