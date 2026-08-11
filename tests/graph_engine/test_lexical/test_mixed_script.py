"""Tests for mixed-script / homoglyph detection."""

from __future__ import annotations

from graph_engine.lexical.infra_patterns import has_mixed_script


class TestMixedScript:
    def test_cyrillic_latin_mix(self):
        """Hostname con caratteri Cirillici mescolati a Latini."""
        # "аpple.com" con la 'а' cirillica (U+0430) invece della 'a' latina (U+0061)
        cyrillic_a = "а"  # 'а' cirillica
        hostname = f"{cyrillic_a}pple.com"
        assert has_mixed_script(hostname) is True

    def test_all_cyrillic_only(self):
        """Solo Cirillico — un solo script, non mixed."""
        # "пример.рф" (example.rf in Cyrillic)
        hostname = "пример.рф"
        assert has_mixed_script(hostname) is False

    def test_normal_latin_hostname(self):
        assert has_mixed_script("evil.example.com") is False

    def test_latin_with_hyphens_and_numbers(self):
        """Caratteri ASCII non-letter non attivano mixed-script."""
        assert has_mixed_script("my-phish-123.example.com") is False

    def test_punycode_latin(self):
        """Punycode che decodifica a solo Latino → False."""
        assert has_mixed_script("xn--example-9u8h.com") is False

    def test_greek_latin_mix(self):
        """Greco + Latino → True."""
        # 'ο' greca (U+03BF) visivamente identica a 'o' latina
        greek_o = "ο"
        hostname = f"g{greek_o}{greek_o}gle.com"
        assert has_mixed_script(hostname) is True
