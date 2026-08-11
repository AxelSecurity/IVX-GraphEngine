"""Tests for Shannon entropy and DGA scoring."""

from __future__ import annotations

from graph_engine.lexical.entropy import dga_score, shannon_entropy


class TestShannonEntropy:
    def test_uniform_distribution(self):
        # Ogni carattere diverso → massima entropia
        e = shannon_entropy("abcdefgh")
        assert e > 2.5  # log2(8) = 3.0, vicino al massimo

    def test_all_same_character(self):
        e = shannon_entropy("aaaaaa")
        assert e == 0.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_human_readable_domain_has_low_entropy(self):
        e = shannon_entropy("example")
        # Parole reali hanno entropia moderata
        assert e < 2.8


class TestDGAScore:
    def test_real_word_domain_low_score(self):
        """Dominio con parole reali → punteggio DGA basso."""
        score = dga_score("example.com")
        assert score < 0.5

    def test_italian_brand_domain_low_score(self):
        score = dga_score("inps.it")
        assert score < 0.5

    def test_dga_like_domain_high_score(self):
        """Stringa random tipo DGA → punteggio alto."""
        score = dga_score("xkqzvbnmasdf.com")
        # Alto rapporto consonanti/vocali, entropia alta
        assert score > 0.4  # almeno moderatamente alto

    def test_dga_with_digits_high_score(self):
        """DGA con molte cifre → punteggio alto."""
        score = dga_score("x7k9q2z5v8b1.com")
        assert score > 0.4

    def test_extreme_dga_very_high(self):
        """DGA estrema: tutte consonanti, nessuna vocale."""
        score = dga_score("xkqzvbnsdfg.com")
        assert score >= 0.40  # zero vocali → forte segnale C/V

    def test_normal_domain_with_numbers(self):
        """Dominio normale con numeri (es. office365) → punteggio basso o moderato."""
        score = dga_score("office365.com")
        # Ha vocale e consonanti bilanciate
        assert score < 0.6
