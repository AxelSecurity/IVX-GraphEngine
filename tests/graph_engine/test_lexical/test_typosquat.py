"""Tests for typosquat detection."""

from __future__ import annotations

from graph_engine.lexical.typosquat import (
    _registrable_domain,
    check_typosquat,
    damerau_levenshtein,
)


class TestDamerauLevenshtein:
    def test_identical_strings(self):
        assert damerau_levenshtein("inps", "inps") == 0

    def test_one_substitution(self):
        assert damerau_levenshtein("inps", "imps") == 1  # n→m sub

    def test_one_deletion(self):
        assert damerau_levenshtein("inps", "ins") == 1

    def test_one_insertion(self):
        assert damerau_levenshtein("ins", "inps") == 1

    def test_transposition(self):
        assert damerau_levenshtein("inps", "insp") == 1

    def test_empty_string(self):
        assert damerau_levenshtein("", "abc") == 3
        assert damerau_levenshtein("abc", "") == 3


class TestRegistrableDomain:
    def test_simple_tld(self):
        assert _registrable_domain("evil.example.com") == "example.com"

    def test_subdomain(self):
        assert _registrable_domain("login.phish.evil.com") == "evil.com"

    def test_two_part_tld(self):
        assert _registrable_domain("phish.example.co.uk") == "example.co.uk"

    def test_bare_domain(self):
        assert _registrable_domain("example.com") == "example.com"

    def test_italian_pa_domain(self):
        assert _registrable_domain("cittadino.inps.it") == "inps.it"


class TestTyposquatCheck:
    def test_identical_to_known_brand_returns_none(self):
        """Dominio identico a uno noto → non è typosquat (è il sito vero)."""
        result = check_typosquat("login.inps.it")  # reg domain = inps.it
        assert result is None

    def test_one_char_difference(self):
        """Variante a 1 carattere di distanza → match."""
        # "inpx.it" vs "inps.it" — 1 sostituzione
        result = check_typosquat("inpx.it")
        assert result is not None
        assert result["distance"] == 1
        assert result["brand"] == "INPS"

    def test_two_char_difference(self):
        """Variante a 2 caratteri di distanza → match."""
        # "inpos.it" vs "inps.it" — 1 inserimento + 1 sostituzione?
        # Actually: "inpos" vs "inps": p==p, o→null (del), s==s → d=1. Too simple.
        # "inns.it" vs "inps.it": n→p substitution = 1. Hmm.
        # "inpss.it" vs "inps.it": insertion of extra 's' = 1.
        # Let's use "imqs.it" vs "inps.it": m→n, q→p = 2 substitutions.
        result = check_typosquat("imqs.it")
        assert result is not None
        assert result["distance"] == 2
        assert result["brand"] == "INPS"

    def test_completely_unrelated_domain(self):
        """Dominio senza alcuna somiglianza → None."""
        result = check_typosquat("completely-different-xyz.org")
        assert result is None

    def test_subdomain_of_known_brand_not_typosquat(self):
        """Sottodominio di un brand noto — registrabile identico → None."""
        result = check_typosquat("webmail.poste.it")
        assert result is None  # reg domain = poste.it, identico

    def test_fake_poste_domain(self):
        """Variante di 'poste.it' con 1 carattere diverso."""
        # "posti.it" vs "poste.it" — 1 sostituzione (i→e)
        result = check_typosquat("posti.it")
        assert result is not None
        assert result["distance"] == 1
        assert result["brand"] in ("Poste Italiane",)  # one of the brands with poste.it
