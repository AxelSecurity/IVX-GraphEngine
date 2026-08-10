"""Credential injection — detect form fields, submit canary values.

Implements the "Credential canary" section from ARCHITECTURE_L4.md:
- Detect email / password / OTP fields via DOM inspection.
- Submit canary credentials and capture the exfiltration endpoint.
- Check the endpoint against a known-IdP list.
- Stop immediately when an OTP/MFA field is found (strong live-attack signal).
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import Page

from graph_engine.canary_identity import CANARY_EMAIL, CANARY_PASSWORD

# ---------------------------------------------------------------------------
# Known Identity Providers — if the form POSTs to one of these domains it is
# a strong signal of an AiTM / reverse-proxy attack in progress.
# ---------------------------------------------------------------------------

_KNOWN_IDP_DOMAINS: frozenset[str] = frozenset({
    "login.microsoftonline.com",
    "accounts.google.com",
    "login.yahoo.com",
    "appleid.apple.com",
})


def check_known_idp(url: str) -> Optional[str]:
    """Return the matching IdP domain if *url* belongs to a known IdP."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return None
    host_lower = host.lower()
    for domain in _KNOWN_IDP_DOMAINS:
        if host_lower == domain or host_lower.endswith("." + domain):
            return domain
    return None


# ---------------------------------------------------------------------------
# JavaScript detection snippets (run inside the browser via page.evaluate)
# ---------------------------------------------------------------------------

_DETECT_EMAIL_JS = """() => {
    const keywords = /\\b(email|e-mail|user|username|login)\\b/;
    const inputs = document.querySelectorAll(
        'input[type="email"], input[type="text"]:not([type])'
    );
    for (const el of inputs) {
        if (el.offsetParent === null) continue;
        const haystack = [
            el.name || '', el.id || '', el.placeholder || '',
            el.getAttribute('aria-label') || ''
        ].join(' ').toLowerCase();
        if (keywords.test(haystack)) {
            if (el.id) return {selector: '#' + CSS.escape(el.id)};
            if (el.name) return {selector: '[name="' + el.name.replace(/"/g, '\\\\"') + '"]'};
            return {selector: 'input[type="email"], input[type="text"]:not([type])'};
        }
    }
    // Fallback: first visible email input
    const emailOnly = document.querySelector('input[type="email"]:not([type="hidden"])');
    if (emailOnly && emailOnly.offsetParent !== null) {
        if (emailOnly.id) return {selector: '#' + CSS.escape(emailOnly.id)};
        return {selector: 'input[type="email"]'};
    }
    return null;
}"""

_DETECT_PASSWORD_JS = """() => {
    const inputs = document.querySelectorAll('input[type="password"]');
    for (const el of inputs) {
        if (el.offsetParent === null) continue;
        if (el.id) return {selector: '#' + CSS.escape(el.id)};
        if (el.name) return {selector: '[name="' + el.name.replace(/"/g, '\\\\"') + '"]'};
        return {selector: 'input[type="password"]'};
    }
    return null;
}"""

_DETECT_OTP_JS = """() => {
    // ---- pattern A: single input with OTP-ish attributes ------------------
    const otpKeywords = /\\b(code|otp|verification|authenticator|token|2fa|mfa|pin|one.?time|passcode)\\b/;
    for (const el of document.querySelectorAll('input:not([type="hidden"])')) {
        if (el.offsetParent === null) continue;
        const haystack = [
            el.name || '', el.id || '', el.placeholder || '',
            el.getAttribute('aria-label') || '', el.autocomplete || ''
        ].join(' ').toLowerCase();
        if (otpKeywords.test(haystack)) {
            return {found: true, kind: 'single'};
        }
    }
    // ---- pattern B: group of short numeric inputs (split OTP boxes) --------
    const maybeOtp = [];
    for (const el of document.querySelectorAll(
        'input[type="number"], input[type="tel"], ' +
        'input[type="text"][inputmode="numeric"], ' +
        'input:not([type])[maxlength="1"], input[maxlength="2"]'
    )) {
        if (el.offsetParent === null) continue;
        const maxlen = parseInt(el.getAttribute('maxlength') || '99', 10);
        if (maxlen >= 1 && maxlen <= 2) maybeOtp.push(el);
    }
    if (maybeOtp.length >= 3) return {found: true, kind: 'group', count: maybeOtp.length};
    return {found: false};
}"""

_FIND_SUBMIT_JS = """(fieldSelector) => {
    const field = document.querySelector(fieldSelector);
    if (!field) return null;
    // Walk up to the nearest form.
    let form = field.closest('form');
    if (!form) form = document;
    // Priority: input[type=submit] > button[type=submit] > button
    const candidates = [
        ...form.querySelectorAll(
            'input[type="submit"], button[type="submit"], ' +
            'button:not([type]), [role="button"]'
        ),
    ].filter(el => el.offsetParent !== null);
    if (!candidates.length) return null;
    const el = candidates[0];
    if (el.id) return {selector: '#' + CSS.escape(el.id)};
    const text = (el.textContent || el.value || '').trim().slice(0, 60);
    if (text) return {selector: el.tagName.toLowerCase() + ':has-text("' + text.replace(/"/g, '\\\\"') + '")'};
    return {selector: candidates[0].tagName.toLowerCase()};
}"""


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


async def _eval_selector(page: Page, js: str) -> Optional[str]:
    """Run *js* and return the ``selector`` field, or ``None``."""
    try:
        result = await page.evaluate(js)
    except Exception:
        return None
    if result and isinstance(result, dict):
        return result.get("selector")
    return None


async def detect_email_field(page: Page) -> Optional[str]:
    """CSS selector for the first visible email / username input, or ``None``."""
    return await _eval_selector(page, _DETECT_EMAIL_JS)


async def detect_password_field(page: Page) -> Optional[str]:
    """CSS selector for the first visible password input, or ``None``."""
    return await _eval_selector(page, _DETECT_PASSWORD_JS)


async def detect_otp_field(page: Page) -> bool:
    """Return ``True`` when the page contains an OTP / MFA input field.

    Detects both:
    - A single input whose attributes mention codes / tokens / 2FA.
    - A group of 3+ short numeric inputs (split OTP digit boxes).
    """
    try:
        result = await page.evaluate(_DETECT_OTP_JS)
    except Exception:
        return False
    if result and isinstance(result, dict):
        return bool(result.get("found"))
    return False


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------


async def submit_field(
    page: Page,
    field_selector: str,
    value: str,
    field_kind: str,
) -> dict:
    """Fill *field_selector* with *value*, click the nearest submit button,
    and capture the resulting network request.

    Returns ``{endpoint, method, status, captured}`` where *captured* is
    ``True`` when a POST request was intercepted.
    """
    captured: Optional[dict] = None

    async def _on_request(request):
        nonlocal captured
        if captured is None and request.method in ("POST", "GET"):
            captured = {
                "endpoint": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
            }

    # 1. Fill the field -------------------------------------------------------
    locator = page.locator(field_selector).first
    await locator.fill(value)
    await asyncio.sleep(0.3)

    # 2. Find the submit button -----------------------------------------------
    submit_result = await page.evaluate(_FIND_SUBMIT_JS, field_selector)
    if not submit_result or not isinstance(submit_result, dict):
        return {
            "endpoint": "",
            "method": "",
            "status": -1,
            "captured": False,
            "error": "no submit button found",
        }
    submit_selector = submit_result.get("selector", "")
    if not submit_selector:
        return {
            "endpoint": "",
            "method": "",
            "status": -1,
            "captured": False,
            "error": "empty submit selector",
        }

    # 3. Capture the next network request -------------------------------------
    page.on("request", _on_request)

    # 4. Click submit ---------------------------------------------------------
    try:
        await page.locator(submit_selector).first.click(timeout=5000)
    except Exception as exc:
        page.remove_listener("request", _on_request)
        return {
            "endpoint": "",
            "method": "",
            "status": -1,
            "captured": False,
            "error": f"click failed: {exc}",
        }

    # 5. Wait for the request to be observed ----------------------------------
    await asyncio.sleep(2.0)

    # Try to catch any navigation.
    try:
        await page.wait_for_load_state("networkidle", timeout=3000)
    except Exception:
        pass

    page.remove_listener("request", _on_request)

    # 6. Build result ---------------------------------------------------------
    if captured is None:
        return {
            "endpoint": page.url,
            "method": "",
            "status": -1,
            "captured": False,
            "error": "no POST request captured",
        }

    return {
        "endpoint": captured["endpoint"],
        "method": captured["method"],
        "status": 0,  # will be filled by response listener in explorer
        "captured": True,
        "field_kind": field_kind,
        "post_data": captured.get("post_data"),
    }
