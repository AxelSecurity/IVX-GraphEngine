"""Passive form-field scanner — read-only, no fill, no click, no submit.

This utility enumerates visible input / select / textarea elements on a
page to produce a lightweight signal for classification.  It never
mutates page state.
"""

from __future__ import annotations

from typing import Optional

from playwright.async_api import Page


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
