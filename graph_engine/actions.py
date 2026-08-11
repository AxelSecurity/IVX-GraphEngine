"""Actionable element scoring for interactive BFS transitions.

Implements the "Actionable scoring" section from ARCHITECTURE.md:
enumerate every visible button / link / role=button / input[type=submit],
score each one by keyword match + visual salience + position, and return
the list sorted by combined score descending.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from playwright.async_api import Page

# ---------------------------------------------------------------------------
# Tunable weights (documented rationale next to each constant)
# ---------------------------------------------------------------------------

# Combined-score blending factors:
W_KEYWORD = 0.50   # keyword match dominates — the action verb IS the intent
W_SALIENCE = 0.30  # visual prominence: bigger + more central = more likely
W_POSITION = 0.20  # above-the-fold bonus

# Salience sub-factors:
W_AREA = 0.60       # element area relative to viewport
W_CENTER_DIST = 0.40  # proximity to viewport centre

# Position bonus:
ABOVE_FOLD_SCORE = 1.0
BELOW_FOLD_SCORE = 0.3

# ---------------------------------------------------------------------------
# Action keywords — partial, case-insensitive matching
# ---------------------------------------------------------------------------

_ACTION_KEYWORDS: tuple[str, ...] = (
    "verify",
    "continue",
    "view document",
    "unlock",
    "sign in",
    "proceed",
    "open",
    "download",
    "confirm",
    "next",
    "submit",
    "accept",
    "allow",
    "login",
    "log in",
    "register",
    "sign up",
    "get started",
    "try again",
    "retry",
    "update",
    "install",
    "enable",
    "access",
    "view",
    "read more",
    "show more",
    "expand",
    "play",
    "start",
)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class ActionCandidate:
    """One clickable element with its selector, label, score, and geometry."""

    selector: str
    text: str
    combined_score: float
    bounding_box: dict = field(default_factory=dict)
    # bounding_box keys: x, y, width, height (all float)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def enumerate_actionable(page: Page) -> list[ActionCandidate]:
    """Find visible interactive elements, score them, return sorted candidates.

    Strategy (runs as a single ``page.evaluate()`` call):
    1. Query all ``button, a[href], [role="button"], input[type="submit"]``.
    2. Drop elements with zero-area bounding boxes or outside the viewport.
    3. For each survivor build a unique CSS selector and compute three scores.
    4. Return the list sorted by ``combined_score`` descending.
    """
    raw: list[dict] = await page.evaluate(_SCORING_SCRIPT)
    candidates = [
        ActionCandidate(
            selector=item["selector"],
            text=item["text"],
            combined_score=round(item["combined_score"], 4),
            bounding_box=item["bounding_box"],
        )
        for item in raw
    ]
    return candidates


# ---------------------------------------------------------------------------
# JavaScript payload executed inside the browser context
# ---------------------------------------------------------------------------

_SCORING_SCRIPT = """() => {
    const KEYWORDS = """ + str(list(_ACTION_KEYWORDS)) + """;

    // ---- helpers ----------------------------------------------------------
    const norm = (s) => (s || '').toLowerCase().replace(/\\s+/g, ' ').trim();

    const keywordScore = (text, ariaLabel) => {
        const haystack = norm(text) + ' ' + norm(ariaLabel);
        for (const kw of KEYWORDS) {
            if (haystack.includes(kw)) return 1.0;   // full match
        }
        // partial-token match: any keyword token inside any haystack token
        const tokens = new Set(haystack.split(/\\s+/).filter(Boolean));
        for (const kw of KEYWORDS) {
            for (const kt of kw.split(/\\s+/)) {
                for (const t of tokens) {
                    if (t.includes(kt) && kt.length >= 3) return 0.6;
                }
            }
        }
        return 0.0;
    };

    const buildSelector = (el) => {
        // Prefer id, else use tag + trimmed text via :has-text().
        if (el.id) return '#' + CSS.escape(el.id);
        const tag = el.tagName.toLowerCase();
        const raw = (el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120);
        if (raw) {
            // Escape double-quotes for the :has-text() argument.
            return tag + ':has-text("' + raw.replace(/"/g, '\\\\"') + '")';
        }
        // Last resort: tag + nth-of-type path.
        let path = tag;
        if (el.className && typeof el.className === 'string') {
            const cls = el.className.trim().split(/\\s+/).slice(0, 2).join('.');
            if (cls) path += '.' + cls;
        }
        return path;
    };

    // ---- main loop --------------------------------------------------------
    const selectors = 'button, a[href], [role="button"], input[type="submit"]';
    const nodes = document.querySelectorAll(selectors);

    const vpW = window.innerWidth;
    const vpH = window.innerHeight;
    const vpArea = vpW * vpH;
    const cx = vpW / 2;
    const cy = vpH / 2;
    const maxDist = Math.sqrt(cx * cx + cy * cy);

    const results = [];
    for (let i = 0; i < nodes.length; i++) {
        const el = nodes[i];
        const rect = el.getBoundingClientRect();

        // Visibility / size filter
        if (rect.width < 4 || rect.height < 4) continue;
        if (rect.bottom < 0 || rect.top > vpH) continue;
        if (rect.right < 0 || rect.left > vpW) continue;

        // ---- scores -------------------------------------------------------
        const text = (el.textContent || '').replace(/\\s+/g, ' ').trim();
        const ariaLabel = el.getAttribute('aria-label') || '';

        const kw = keywordScore(text, ariaLabel);

        const area = rect.width * rect.height;
        const areaScore = Math.min(area / (vpArea * 0.25), 1.0);  // saturate at 25 % of viewport
        const distX = (rect.x + rect.width / 2) - cx;
        const distY = (rect.y + rect.height / 2) - cy;
        const dist = Math.sqrt(distX * distX + distY * distY);
        const centreScore = 1.0 - Math.min(dist / maxDist, 1.0);

        const salience = """ + str(W_AREA) + """ * areaScore + """ + str(W_CENTER_DIST) + """ * centreScore;

        // above-the-fold: element top edge in upper half of viewport
        const position = rect.top < vpH * 0.6 ? """ + str(ABOVE_FOLD_SCORE) + """ : """ + str(BELOW_FOLD_SCORE) + """;

        const combined = """ + str(W_KEYWORD) + """ * kw
                       + """ + str(W_SALIENCE) + """ * salience
                       + """ + str(W_POSITION) + """ * position;

        results.push({
            selector: buildSelector(el),
            text: text.slice(0, 200),
            combined_score: combined,
            bounding_box: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        });
    }

    results.sort((a, b) => b.combined_score - a.combined_score);
    return results;
}"""
