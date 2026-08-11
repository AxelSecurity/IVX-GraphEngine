"""Integration test for the full L0 ingestion pipeline."""

from __future__ import annotations

from graph_engine.ingestion.pipeline import ingest


class TestIngestEndToEnd:
    def test_plain_url_passes_through(self):
        result = ingest("https://evil.example/login")
        assert result["input_url"] == "https://evil.example/login"
        assert result["canonical_url"] == "https://evil.example/login"
        assert len(result["url_hash"]) == 64
        assert result["unwrap_chain"] == []
        assert result["nested_payloads"] == []

    def test_defanged_safelinks_unwrapped(self):
        # defanged safelinks → refang → unwrap safelinks
        from urllib.parse import quote

        target = "https://evil.example/phish"
        safelinks = (
            "https://emea01.safelinks.protection.outlook.com/"
            "?url=" + quote(target, safe="") + "&data=05%7C02%7C..."
        )
        defanged = "hxxps://emea01.safelinks.protection.outlook[.]com/?url=" + quote(target, safe="") + "&data=05%7C02%7C..."

        result = ingest(defanged)
        assert result["input_url"] == defanged  # original preserved verbatim
        assert result["canonical_url"] == target
        assert len(result["unwrap_chain"]) == 1
        assert result["unwrap_chain"][0]["wrapper_type"] == "safe-links"

    def test_input_url_always_preserved(self):
        """The original (possibly defanged) input_url is NEVER overwritten."""
        raw = "hxxps[://]evil[.]example[.]com/login"
        result = ingest(raw)
        assert result["input_url"] == raw
        # The canonical form is clean
        assert "[.]" not in result["canonical_url"]
        assert "hxxps" not in result["canonical_url"]

    def test_nested_payloads_extracted(self):
        import base64

        inner = "https://evil.example/c2"
        encoded = base64.b64encode(inner.encode()).decode()
        url = f"https://evil.example/?q={encoded}"
        result = ingest(url)
        assert len(result["nested_payloads"]) >= 1
        assert any(
            p["decoded"] == inner and p["kind"] == "url"
            for p in result["nested_payloads"]
        )
