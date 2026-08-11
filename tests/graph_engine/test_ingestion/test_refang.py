"""Tests for URL refanging."""

from __future__ import annotations

import pytest

from graph_engine.ingestion.refang import refang


class TestRefangCommonPatterns:
    """Every supported defanging pattern must be reversed."""

    def test_hxxp_scheme(self):
        assert refang("hxxp://evil.example") == "http://evil.example"
        assert refang("hxxps://evil.example") == "https://evil.example"

    def test_hxxp_scheme_with_brackets(self):
        assert refang("hxxp[://]evil.example") == "http://evil.example"

    def test_bracket_dots(self):
        assert refang("evil[.]example[.]com") == "evil.example.com"
        assert refang("evil(.)example(.)com") == "evil.example.com"
        assert refang("evil{.}example{.}com") == "evil.example.com"

    def test_bracket_colon(self):
        assert refang("http[:]//evil.example") == "http://evil.example"

    def test_bracket_at(self):
        assert refang("user[at]example.com") == "user@example.com"
        assert refang("user[@]example.com") == "user@example.com"

    def test_wxw_prefix(self):
        assert refang("wxw.evil.example") == "www.evil.example"

    def test_spaced_scheme(self):
        assert refang("h t t p : / / evil.example") == "http://evil.example"
        assert refang("h t t p s : / / evil.example") == "https://evil.example"

    def test_dot_slash_words(self):
        assert refang("evil dot example dot com") == "evil.example.com"
        assert refang("evil dot example dot com slash login") == \
            "evil.example.com/login"


class TestRefangIdempotence:
    """refang on an already-clean URL must be a no-op."""

    def test_clean_url_unchanged(self):
        url = "https://evil.example/login?user=test"
        assert refang(url) == url

    def test_double_refang(self):
        url = "hxxps[://]evil[.]example[.]com"
        once = refang(url)
        twice = refang(once)
        assert twice == once
        assert "hxxp" not in twice
        assert "[.]" not in twice

    def test_partially_fanged_stays_stable(self):
        url = "hxxps://evil[.]example.com"
        once = refang(url)
        twice = refang(once)
        assert twice == once

    def test_no_url_no_crash(self):
        assert refang("just some text") == "just some text"
        assert refang("") == ""
