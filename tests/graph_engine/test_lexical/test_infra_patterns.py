"""Tests for abuse-prone infrastructure detection."""

from __future__ import annotations

from graph_engine.lexical.infra_patterns import (
    check_abuse_prone_infra,
    is_ip_literal,
)


class TestAbuseProneInfra:
    def test_cloudflare_workers(self):
        assert check_abuse_prone_infra("evil-phish.workers.dev") == "cloudflare-workers"

    def test_cloudflare_pages(self):
        assert check_abuse_prone_infra("phish.pages.dev") == "cloudflare-pages"

    def test_cloudflare_r2(self):
        assert check_abuse_prone_infra("malware-storage.r2.dev") == "cloudflare-r2"

    def test_azure_blob(self):
        assert check_abuse_prone_infra(
            "phish.blob.core.windows.net"
        ) == "azure-blob"

    def test_firebase_web_app(self):
        assert check_abuse_prone_infra("phish-123.web.app") == "firebase-hosting"

    def test_firebaseapp(self):
        assert check_abuse_prone_infra("phish-abc.firebaseapp.com") == "firebase-app"

    def test_ipfs_gateway_io(self):
        assert check_abuse_prone_infra(
            "ipfs.io/ipfs/QmHash123"
        ) == "ipfs-gateway"

    def test_ipfs_dweb_link(self):
        assert check_abuse_prone_infra(
            "bafyabc.ipfs.dweb.link"
        ) == "ipfs-gateway"

    def test_cloudflare_ipfs(self):
        assert check_abuse_prone_infra(
            "cloudflare-ipfs.com/ipfs/QmHash"
        ) == "ipfs-gateway"

    def test_trycloudflare_tunnel(self):
        assert check_abuse_prone_infra(
            "random-site.trycloudflare.com"
        ) == "cloudflare-tunnel"

    def test_ngrok_io(self):
        assert check_abuse_prone_infra(
            "abc123.ngrok.io"
        ) == "ngrok-tunnel"

    def test_ngrok_free_app(self):
        assert check_abuse_prone_infra(
            "abc123.ngrok-free.app"
        ) == "ngrok-tunnel"

    def test_loca_lt(self):
        assert check_abuse_prone_infra(
            "random-tunnel.loca.lt"
        ) == "loca-lt-tunnel"

    def test_clean_domain_returns_none(self):
        assert check_abuse_prone_infra("evil.example.com") is None

    def test_legitimate_brand_domain_returns_none(self):
        assert check_abuse_prone_infra("inps.it") is None


class TestIPLiteral:
    def test_ipv4_literal(self):
        assert is_ip_literal("192.168.1.1") is True

    def test_ipv6_literal(self):
        assert is_ip_literal("::1") is True

    def test_ipv6_full(self):
        assert is_ip_literal("2001:db8::1") is True

    def test_ipv6_bracketed(self):
        assert is_ip_literal("[::1]") is True

    def test_hostname_is_not_ip(self):
        assert is_ip_literal("evil.example.com") is False

    def test_empty_string(self):
        assert is_ip_literal("") is False
