"""Tests for passive form-field scanner — scan_form_fields()."""

from __future__ import annotations

import pytest
from playwright.async_api import async_playwright


# ---------------------------------------------------------------------------
# Fixtures (inline HTML — no HTTP server needed)
# ---------------------------------------------------------------------------


_PAGE_WITH_MIXED_FIELDS = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body>
  <form>
    <label for="email">Email address</label>
    <input type="email" id="email" name="email" placeholder="you@example.com">

    <label for="password">Password</label>
    <input type="password" id="password" name="password">

    <label>
      <input type="checkbox" name="remember"> Remember me
    </label>

    <input type="hidden" name="csrf_token" value="abc123">

    <button type="submit" id="btn-login">Sign in</button>
  </form>
</body>
</html>"""

_PAGE_WITH_SELECT_AND_TEXTAREA = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Registration</title></head>
<body>
  <form>
    <label for="country">Country</label>
    <select id="country" name="country">
      <option value="">Select…</option>
      <option value="IT">Italy</option>
    </select>

    <label for="bio">Bio</label>
    <textarea id="bio" name="bio" placeholder="Tell us about yourself"></textarea>

    <input type="file" name="avatar">

    <button type="submit">Register</button>
  </form>
</body>
</html>"""

_PAGE_WITH_CARD_FIELDS = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Payment</title></head>
<body>
  <form>
    <label for="card-number">Card number</label>
    <input type="text" id="card-number" name="card_number" placeholder="•••• •••• •••• ••••">

    <label for="expiry">Expiry</label>
    <input type="text" id="expiry" name="expiry" placeholder="MM/YY">

    <label for="cvv">Security code</label>
    <input type="text" id="cvv" name="cvv" maxlength="4" placeholder="CVV">

    <label for="codice_fiscale">Codice Fiscale</label>
    <input type="text" id="codice_fiscale" name="codice_fiscale">

    <button type="submit">Pay now</button>
  </form>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScanFormFields:
    """scan_form_fields must enumerate fields WITHOUT filling or clicking."""

    async def test_mixed_fields_skips_hidden_and_buttons(self):
        """Hidden inputs, checkboxes, and submit buttons must be excluded."""
        from graph_engine.classifier.form_inventory import scan_form_fields

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_PAGE_WITH_MIXED_FIELDS)
                import asyncio
                await asyncio.sleep(0.2)

                fields = await scan_form_fields(page)

                # Only email + password should be returned (2 visible text-like inputs)
                types = {f["type"] for f in fields}
                assert "hidden" not in types, (
                    f"Hidden inputs must be excluded, got: {types}"
                )
                assert "checkbox" not in types, (
                    f"Checkboxes must be excluded, got: {types}"
                )
                assert "submit" not in types, (
                    f"Submit buttons must be excluded, got: {types}"
                )

                # Email field must have correct label
                email_fields = [f for f in fields if f["type"] == "email"]
                assert len(email_fields) == 1
                assert email_fields[0]["name_or_id"] == "email"
                assert "Email address" in email_fields[0]["nearby_label_text"], (
                    f"Expected 'Email address' label, "
                    f"got: {email_fields[0]['nearby_label_text']}"
                )

                # Password field must be present
                pwd_fields = [f for f in fields if f["type"] == "password"]
                assert len(pwd_fields) == 1
                assert pwd_fields[0]["name_or_id"] == "password"
                assert "Password" in pwd_fields[0]["nearby_label_text"]

            finally:
                await browser.close()

    async def test_select_and_textarea_included_file_excluded(self):
        """Select and textarea are included; file is excluded."""
        from graph_engine.classifier.form_inventory import scan_form_fields

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_PAGE_WITH_SELECT_AND_TEXTAREA)
                import asyncio
                await asyncio.sleep(0.2)

                fields = await scan_form_fields(page)

                types = {f["type"] for f in fields}
                assert "select" in types, (
                    f"Select elements must be included, got: {types}"
                )
                assert "textarea" in types, (
                    f"Textarea elements must be included, got: {types}"
                )
                assert "file" not in types, (
                    f"File inputs must be excluded, got: {types}"
                )

                # Verify label extraction
                country = [f for f in fields if f["type"] == "select"][0]
                assert "Country" in country["nearby_label_text"]

                bio = [f for f in fields if f["type"] == "textarea"][0]
                assert "Bio" in bio["nearby_label_text"]

            finally:
                await browser.close()

    async def test_payment_fields_with_sensitive_labels(self):
        """Card number, CVV, Codice Fiscale — all must be detected."""
        from graph_engine.classifier.form_inventory import scan_form_fields

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(_PAGE_WITH_CARD_FIELDS)
                import asyncio
                await asyncio.sleep(0.2)

                fields = await scan_form_fields(page)

                # All 4 visible inputs must be returned
                assert len(fields) == 4, (
                    f"Expected 4 visible fields, got {len(fields)}: {fields}"
                )

                labels = {f["name_or_id"]: f["nearby_label_text"]
                          for f in fields}

                assert "Card number" in labels.get("card_number", ""), (
                    f"Missing 'Card number' label: {labels}"
                )
                assert "Security code" in labels.get("cvv", ""), (
                    f"Missing 'Security code' label: {labels}"
                )
                assert "Codice Fiscale" in labels.get("codice_fiscale", ""), (
                    f"Missing 'Codice Fiscale' label: {labels}"
                )
                assert "Expiry" in labels.get("expiry", ""), (
                    f"Missing 'Expiry' label: {labels}"
                )

            finally:
                await browser.close()

    async def test_no_fields_returns_empty_list(self):
        """Page with no form elements → empty list."""
        from graph_engine.classifier.form_inventory import scan_form_fields

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.set_content(
                    "<html><body><p>Hello world</p></body></html>"
                )
                import asyncio
                await asyncio.sleep(0.1)

                fields = await scan_form_fields(page)
                assert fields == []

            finally:
                await browser.close()
