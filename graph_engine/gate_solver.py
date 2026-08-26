"""Gate / CAPTCHA solver — wait + simple checkbox only, never real puzzles.

Implements the bare minimum needed to pass "invisible" challenges that
auto-resolve after a short delay (Cloudflare Turnstile, hCaptcha invisible,
reCAPTCHA v3).  For visible checkbox challenges it clicks a single
checkbox inside the provider's iframe.  Real image/audio puzzles are
out of scope — if the gate isn't gone after the checkbox click we bail
out immediately.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from playwright.async_api import Page


# ---------------------------------------------------------------------------
# Known CAPTCHA provider patterns (searched in iframe src attributes)
# ---------------------------------------------------------------------------

_PROVIDER_PATTERNS: list[tuple[str, str]] = [
    ("challenges.cloudflare.com", "cloudflare_turnstile"),
    ("hcaptcha.com", "hcaptcha"),
    ("google.com/recaptcha", "recaptcha"),
]

# ---------------------------------------------------------------------------
# Known checkbox selectors inside CAPTCHA iframes
# ---------------------------------------------------------------------------

_CHECKBOX_SELECTORS: list[str] = [
    'input[type="checkbox"]',
    '.checkbox',
    '#checkbox',
    '[role="checkbox"]',
]


# ---------------------------------------------------------------------------
# JavaScript snippet — collect iframe srcs
# ---------------------------------------------------------------------------

_GET_IFRAME_SRCS_JS = """() => {
    return Array.from(document.querySelectorAll('iframe'))
        .map(el => (el.src || '').trim())
        .filter(s => s.length > 0);
}"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def detect_captcha(page: Page) -> Optional[str]:
    """Return the CAPTCHA provider name found in any iframe on *page*, or ``None``.

    Inspects every iframe's ``src`` attribute for known provider domains.
    """
    try:
        srcs: list[str] = await page.evaluate(_GET_IFRAME_SRCS_JS)
        for src_str in srcs:
            for domain, label in _PROVIDER_PATTERNS:
                if domain in src_str:
                    return label
    except Exception:
        pass
    return None


async def try_pass_gate(
    page: Page, wait_seconds: int = 8, settle_s: float = 3.0
) -> bool:
    """Attempt to pass a detected gate by waiting + optional checkbox click.

    1. Poll for up to *wait_seconds* — many invisible challenges auto-resolve.
    2. If still present, try a single checkbox click inside the provider iframe.
    3. Wait *settle_s* more seconds, then check again.

    Returns ``True`` when the gate has disappeared, ``False`` otherwise.
    Never attempts real puzzle solving (image / audio challenges).
    """
    # ---- phase 1: wait for auto-resolve -----------------------------------
    deadline = time.monotonic() + wait_seconds

    while time.monotonic() < deadline:
        if await detect_captcha(page) is None:
            return True  # gate disappeared on its own
        await asyncio.sleep(1.5)

    # ---- phase 2: try a single checkbox click -----------------------------
    provider = await detect_captcha(page)
    if provider is None:
        return True  # already gone

    checkbox_clicked = False
    for frame in page.frames:
        if frame == page.main_frame:
            continue  # only look inside sub-frames
        for selector in _CHECKBOX_SELECTORS:
            try:
                el = frame.locator(selector).first
                if await el.is_visible(timeout=500):
                    await el.click(timeout=3000)
                    checkbox_clicked = True
                    break
            except Exception:
                continue
        if checkbox_clicked:
            break

    # ---- phase 3: brief settle + final check ------------------------------
    await asyncio.sleep(settle_s)

    return await detect_captcha(page) is None
