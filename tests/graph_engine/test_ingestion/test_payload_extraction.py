"""Tests for nested payload extraction."""

from __future__ import annotations

import base64

from graph_engine.ingestion.payload_extraction import extract_nested_payloads


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class TestBase64UrlPayload:
    def test_valid_url_payload(self):
        inner = "https://evil.example/phish"
        encoded = _b64(inner)
        url = f"https://gateway.example/?token={encoded}"
        payloads = extract_nested_payloads(url)
        assert len(payloads) >= 1
        assert any(p["decoded"] == inner and p["kind"] == "url"
                   for p in payloads)

    def test_valid_email_payload(self):
        inner = "phish@evil.example"
        encoded = _b64(inner)
        url = f"https://gateway.example/?data={encoded}"
        payloads = extract_nested_payloads(url)
        assert len(payloads) >= 1
        assert any(p["decoded"] == inner and p["kind"] == "email"
                   for p in payloads)

    def test_base64_like_but_garbage(self):
        # Looks like base64 but decodes to binary garbage — no match
        garbage = "VGhpcyBpcyBqdXN0IGdhcmJhZ2UhIQ=="  # "This is just garbage!!"
        url = f"https://example.com/?q={garbage}"
        payloads = extract_nested_payloads(url)
        # Neither URL nor email → should not be reported
        assert all(p["kind"] != "url" for p in payloads)
        assert all(p["kind"] != "email" for p in payloads)

    def test_no_payload_present(self):
        url = "https://evil.example/login?user=admin&next=/dashboard"
        payloads = extract_nested_payloads(url)
        assert payloads == []

    def test_payload_in_fragment(self):
        inner = "https://evil.example/landing"
        encoded = _b64(inner)
        url = f"https://gateway.example/page#{encoded}"
        payloads = extract_nested_payloads(url)
        assert any(p["decoded"] == inner and p["kind"] == "url"
                   for p in payloads)

    def test_multiple_payloads_in_same_url(self):
        url_val = _b64("https://evil.example/a")
        email_val = _b64("phish@evil.example")
        url = (
            "https://gateway.example/?"
            f"token={url_val}&cc={email_val}"
        )
        payloads = extract_nested_payloads(url)
        kinds = {p["kind"] for p in payloads}
        assert "url" in kinds
        assert "email" in kinds
