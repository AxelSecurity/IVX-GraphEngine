"""Tests for URL unwrapping — one real case per supported wrapper type."""

from __future__ import annotations

from graph_engine.ingestion.unwrap import unwrap_url


class TestSafeLinks:
    def test_basic_safelinks(self):
        result = unwrap_url(
            "https://emea01.safelinks.protection.outlook.com/"
            "?url=https%3A%2F%2Fevil.example%2Flogin"
            "&data=05%7C02%7C..."
        )
        assert result.final_url == "https://evil.example/login"
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "safe-links"
        assert result.chain[0].input_url.startswith(
            "https://emea01.safelinks.protection.outlook.com"
        )


class TestProofpointV2:
    def test_basic_v2(self):
        """Proofpoint v2: u= parameter is percent-encoded in the query string."""
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v2/url"
            "?u=https%3A%2F%2Fevil.example%2Flogin"
            "&d=DwIGaQ&c=..."
        )
        assert result.final_url == "https://evil.example/login"
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "proofpoint-v2"

    def test_v2_with_substitutions(self):
        """v2 where _ and - in the u= value decode to / and + before unquote."""
        # u= value: "https:__evil.example_login"
        # After _→/: "https://evil.example/login"
        # After -→+: no change (no - chars)
        # unquote: no percent-sequences → "https://evil.example/login"
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v2/url"
            "?u=https:__evil.example_login"
            "&d=DwIGaQ&c=..."
        )
        assert result.final_url == "https://evil.example/login"
        assert result.chain[0].wrapper_type == "proofpoint-v2"

    def test_v2_non_proofpoint_host_ignored(self):
        """A /v2/ path on a non-Proofpoint host is not matched."""
        # Use a query param name that won't trigger open-redirect
        result = unwrap_url(
            "https://other.example.com/v2/url"
            "?enc=https://evil.example/login"
        )
        # No wrapper matched → passes through
        assert result.final_url == "https://other.example.com/v2/url?enc=https://evil.example/login"
        assert result.chain == []


class TestProofpointV3:
    def test_basic_v3(self):
        # v3: /v3/__<encoded_target>__;<checksum>__
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v3/"
            "__https://evil.example/login__;!!ABC123!def$"
        )
        assert result.final_url == "https://evil.example/login"
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "proofpoint-v3"

    def test_v3_percent_encoded_target(self):
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v3/"
            "__https%3A%2F%2Fevil.example%2Fphish__;!!checksum!!"
        )
        assert result.final_url == "https://evil.example/phish"
        assert result.chain[0].wrapper_type == "proofpoint-v3"


class TestMimecast:
    def test_basic_mimecast(self):
        result = unwrap_url(
            "https://protect-us.mimecast.com/s/abc123?"
            "url=https://evil.example/login"
        )
        assert result.final_url == "https://evil.example/login"
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "mimecast"

    def test_mimecast_opaque(self):
        """When no url= param, final_url stays as mimecast wrapper."""
        result = unwrap_url(
            "https://protect-us.mimecast.com/s/abc123?x=yyy"
        )
        # No decodable target → stays as-is, empty chain
        assert result.final_url.startswith("https://protect-us.mimecast.com")
        assert len(result.chain) == 0


class TestBarracuda:
    def test_basic_barracuda(self):
        result = unwrap_url(
            "https://linkprotect.cudasvc.com/url"
            "?a=https%3A%2F%2Fevil.example%2Flogin"
        )
        assert result.final_url == "https://evil.example/login"
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "barracuda"


class TestOpenRedirect:
    def test_url_param(self):
        result = unwrap_url(
            "https://trusted.example.com/redirect"
            "?url=https://evil.example/login"
        )
        assert result.final_url == "https://evil.example/login"
        assert result.chain[0].wrapper_type == "open-redirect"

    def test_next_param(self):
        result = unwrap_url(
            "https://trusted.example.com/login"
            "?next=https://evil.example/dashboard"
        )
        assert result.final_url == "https://evil.example/dashboard"
        assert result.chain[0].wrapper_type == "open-redirect"


class TestNestedUnwrap:
    def test_safelinks_wrapping_proofpoint(self):
        """SafeLinks outer → Proofpoint v2 inner."""
        # inner: proofpoint v2 URL
        proofpoint_url = (
            "https://urldefense.proofpoint.com/v2/url"
            "?u=https://evil.example/phish&d=..."
        )
        # outer: safelinks wrapping the proofpoint URL
        from urllib.parse import quote
        outer = (
            "https://emea01.safelinks.protection.outlook.com/"
            "?url=" + quote(proofpoint_url, safe="")
            + "&data=05%7C02%7C..."
        )
        result = unwrap_url(outer)
        assert result.final_url == "https://evil.example/phish"
        assert len(result.chain) == 2
        assert result.chain[0].wrapper_type == "safe-links"
        assert result.chain[1].wrapper_type == "proofpoint-v2"

    def test_max_hops_limits_depth(self):
        """Wrapper chain longer than max_hops is truncated."""
        # Construct a self-referencing loop: open-redirect pointing to itself
        from urllib.parse import quote
        inner = "https://evil.example/final"
        # Create URL that redirects to itself via url= param
        loop = "https://a.example/r?url=" + quote(inner, safe="")
        result = unwrap_url(loop, max_hops=1)
        assert result.final_url == inner
        assert len(result.chain) == 1


class TestNoWrapper:
    def test_plain_url_passes_through(self):
        result = unwrap_url("https://evil.example/login")
        assert result.final_url == "https://evil.example/login"
        assert result.chain == []

    def test_non_http_url_passes_through(self):
        result = unwrap_url("ftp://files.example/data")
        assert result.final_url == "ftp://files.example/data"
        assert result.chain == []
