"""Passive form-field scanner — read-only, no fill, no click, no submit.

This utility enumerates visible input / select / textarea elements on a
page to produce a lightweight signal for classification.  It never
mutates page state.
"""

from __future__ import annotations

import asyncio

from playwright.async_api import Page

# Iframe dei CAPTCHA/anti-bot: il loro contenuto ("Verify you are
# human", checkbox) non dice nulla sulla pagina e confonderebbe L5.
_SKIP_FRAME_MARKERS = (
    "challenges.cloudflare.com",
    "hcaptcha.com",
    "google.com/recaptcha",
    "recaptcha.net",
)
_MAX_FRAMES = 5
_FRAME_EVAL_TIMEOUT_S = 2.0
_MAX_FRAME_TEXT_CHARS = 1500

_FRAME_TEXT_SCRIPT = """() => (document.body ? document.body.innerText : '')
    .replace(/\\s+/g, ' ').trim().slice(0, """ + str(_MAX_FRAME_TEXT_CHARS) + """)"""


async def scan_form_fields(page: Page) -> list[dict]:
    """Return metadata for every visible form field on the page.

    Each dict has:
        tag:        element tag name (input | select | textarea)
        type:       HTML ``type`` attribute (empty string if absent)
        name_or_id: ``name`` or ``id`` attribute (first non-empty)
        nearby_label_text:  text of an associated ``<label>`` or
                            preceding sibling text (trimmed)

    Hidden inputs, buttons, submits, checkboxes, radios, and file
    pickers are deliberately excluded — they add noise without signal
    for phishing classification.
    """
    raw: list[dict] = await page.evaluate(_SCAN_SCRIPT)
    return raw


async def scan_child_frames(page: Page) -> tuple[list[dict], list[dict]]:
    """Campi form e testo visibile degli IFRAME della pagina (sola lettura).

    Molti kit caricano il form di login dentro un iframe: lo scan del solo
    documento principale non lo vede.  Per ogni frame figlio (max
    ``_MAX_FRAMES``, iframe dei CAPTCHA esclusi) restituisce:

    - i campi form, con in più ``frame_url``;
    - ``{"url", "text"}`` col testo visibile (troncato), solo per i frame
      con testo o campi.

    Best-effort: un frame che non risponde entro ``_FRAME_EVAL_TIMEOUT_S``
    o che si stacca durante la lettura viene saltato.
    """
    fields: list[dict] = []
    texts: list[dict] = []
    examined = 0
    for frame in page.frames:
        if frame == page.main_frame:
            continue
        url = frame.url or ""
        if any(marker in url for marker in _SKIP_FRAME_MARKERS):
            continue
        if examined >= _MAX_FRAMES:
            break
        examined += 1
        try:
            frame_fields = await asyncio.wait_for(
                frame.evaluate(_SCAN_SCRIPT), _FRAME_EVAL_TIMEOUT_S
            )
            text = await asyncio.wait_for(
                frame.evaluate(_FRAME_TEXT_SCRIPT), _FRAME_EVAL_TIMEOUT_S
            )
        except Exception:
            continue
        frame_fields = frame_fields if isinstance(frame_fields, list) else []
        text = text if isinstance(text, str) else ""
        for field in frame_fields:
            if isinstance(field, dict):
                fields.append(dict(field, frame_url=url))
        if text or frame_fields:
            texts.append({"url": url, "text": text})
    return fields, texts


# ---------------------------------------------------------------------------
# JavaScript payload — runs entirely in the browser, zero DOM mutations
# ---------------------------------------------------------------------------

_SCAN_SCRIPT = """() => {
    const EXCLUDED_TYPES = new Set([
        'hidden', 'submit', 'button', 'reset', 'image',
        'checkbox', 'radio', 'file', 'color', 'range',
    ]);

    /** Return the closest human-readable label for *el*. */
    function findLabel(el) {
        // <label for="id"> — explicit association
        if (el.id) {
            const lbl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
            if (lbl) return lbl.textContent.replace(/\\s+/g, ' ').trim();
        }
        // Wrapping <label>
        const wrap = el.closest('label');
        if (wrap) {
            const copy = wrap.cloneNode(true);
            // Remove the input itself from clone to get the label-only text
            const inputs = copy.querySelectorAll('input, select, textarea');
            inputs.forEach(n => n.remove());
            const txt = (copy.textContent || '').replace(/\\s+/g, ' ').trim();
            if (txt) return txt;
        }
        // aria-labelledby
        const labelledBy = el.getAttribute('aria-labelledby');
        if (labelledBy) {
            const ref = document.getElementById(labelledBy);
            if (ref) return ref.textContent.replace(/\\s+/g, ' ').trim();
        }
        // aria-label
        const aria = el.getAttribute('aria-label');
        if (aria) return aria.replace(/\\s+/g, ' ').trim();
        // placeholder fallback
        const ph = el.getAttribute('placeholder');
        if (ph) return ph.replace(/\\s+/g, ' ').trim();
        // Preceding sibling text (heuristic, troncato a 60 caratteri)
        let prev = el.previousElementSibling;
        while (prev) {
            const txt = (prev.textContent || '').replace(/\\s+/g, ' ').trim();
            if (txt) return txt.slice(0, 60);
            prev = prev.previousElementSibling;
        }
        return '';
    }

    const results = [];
    const nodes = document.querySelectorAll('input, select, textarea');

    for (let i = 0; i < nodes.length; i++) {
        const el = nodes[i];
        const tag = el.tagName.toLowerCase();
        let type = (el.getAttribute('type') || '').toLowerCase();
        if (tag === 'textarea') type = 'textarea';
        if (tag === 'select') type = 'select';

        // Exclude non-signal types
        if (EXCLUDED_TYPES.has(type)) continue;

        // Visibility check: must have non-zero bounding rect
        const rect = el.getBoundingClientRect();
        if (rect.width < 4 || rect.height < 4) continue;

        const nameOrId = el.name || el.id || '';

        results.push({
            tag: tag,
            type: type,
            name_or_id: nameOrId,
            nearby_label_text: findLabel(el),
        });
    }

    return results;
}"""
