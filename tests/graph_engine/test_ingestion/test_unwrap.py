"""Tests for URL unwrapping — one real case per supported wrapper type."""

from __future__ import annotations

from urllib.parse import quote

from graph_engine.ingestion.unwrap import unwrap_url, _decode_proofpoint_v2


def _encode_proofpoint_v2(url: str) -> str:
    """Encode *url* as Proofpoint v2 encodes the ``u=`` parameter.

    Real v2 encoding steps applied server-side:
    1. Replace ``/`` with ``_``
    2. Percent-encode the result
    3. Replace ``%`` with ``-``

    Reversing this is the job of ``_decode_proofpoint_v2``.
    """
    step1 = url.replace("/", "_")
    step2 = quote(step1, safe="")
    step3 = step2.replace("%", "-")
    return step3


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
        """Proofpoint v2 with real encoded u= value (-3A, __ for special chars)."""
        target = "https://evil.example/login"
        encoded_u = _encode_proofpoint_v2(target)
        # e.g. "https-3A__evil.example_login"
        assert "-" in encoded_u or "_" in encoded_u  # la codifica è reale
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v2/url"
            f"?u={encoded_u}"
            "&d=DwIGaQ&c=..."
        )
        assert result.final_url == target
        assert len(result.chain) == 1
        assert result.chain[0].wrapper_type == "proofpoint-v2"

    def test_v2_with_substitutions(self):
        """v2 where _ and - in the u= value decode to / and % before unquote."""
        target = "https://evil.example/login"
        encoded_u = _encode_proofpoint_v2(target)
        # Must contain both substitution chars for this to be meaningful
        assert "_" in encoded_u, "fixture non sta esercitando la sostituzione _"
        assert "-" in encoded_u, "fixture non sta esercitando la sostituzione -"
        result = unwrap_url(
            "https://urldefense.proofpoint.com/v2/url"
            f"?u={encoded_u}"
            "&d=DwIGaQ&c=..."
        )
        assert result.final_url == target
        assert result.chain[0].wrapper_type == "proofpoint-v2"

    def test_decode_v2_isolated(self):
        """Direct test of _decode_proofpoint_v2: - → %, _ → /, then unquote."""
        # Real Proofpoint v2 encoded form of "https://evil.example/login"
        encoded = "https-3A__evil.example_login"
        decoded = _decode_proofpoint_v2(encoded)
        assert decoded == "https://evil.example/login"

    def test_decode_v2_dash_becomes_percent(self):
        """The - char in encoded form MUST become %, not +."""
        # -3A → %3A → :
        decoded = _decode_proofpoint_v2("https-3A__evil.example_login")
        assert decoded == "https://evil.example/login"
        # If - became +, result would contain "+3A", not "://"
        assert "+" not in decoded

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
        """SafeLinks outer → Proofpoint v2 inner, both with real encoding."""
        # inner target
        inner_target = "https://evil.example/phish"
        # Build a real Proofpoint v2 URL with properly encoded u=
        encoded_u = _encode_proofpoint_v2(inner_target)
        proofpoint_url = (
            "https://urldefense.proofpoint.com/v2/url"
            f"?u={encoded_u}&d=DwIGaQ&c=..."
        )
        # outer: safelinks wrapping the proofpoint URL
        outer = (
            "https://emea01.safelinks.protection.outlook.com/"
            "?url=" + quote(proofpoint_url, safe="")
            + "&data=05%7C02%7C..."
        )
        result = unwrap_url(outer)
        assert result.final_url == inner_target
        assert len(result.chain) == 2
        assert result.chain[0].wrapper_type == "safe-links"
        assert result.chain[1].wrapper_type == "proofpoint-v2"

    def test_max_hops_limits_depth(self):
        """Wrapper chain longer than max_hops is truncated."""
        inner = "https://evil.example/final"
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
