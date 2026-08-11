"""Tests for typosquat detection."""

from __future__ import annotations

from unittest.mock import patch

import requests

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

    def test_gov_it_correctly_resolved(self):
        """.gov.it è un TLD a due componenti nella PSL ufficiale.
        Era assente dalla lista manuale _TWO_PART_TLDS — bug corretto con tldextract."""
        assert _registrable_domain("login.inps.gov.it") == "inps.gov.it"
        assert _registrable_domain("www.agenziaentrate.gov.it") == "agenziaentrate.gov.it"

    def test_com_mx_two_part_tld(self):
        """com.mx è nella PSL ufficiale — non era nella lista manuale."""
        assert _registrable_domain("www.example.com.mx") == "example.com.mx"
        assert _registrable_domain("example.com.mx") == "example.com.mx"

    def test_co_in_two_part_tld(self):
        """co.in è nella PSL ufficiale — non era nella lista manuale."""
        assert _registrable_domain("phish.example.co.in") == "example.co.in"

    def test_tld_not_in_old_manual_list(self):
        """Verifica che TLD assenti dalla vecchia lista manuale funzionino.
        Vecchia _TWO_PART_TLDS NON conteneva: gov.it, com.mx, co.in"""
        # Questi tre TLD erano assenti — ora risolti correttamente
        assert _registrable_domain("login.inps.gov.it") == "inps.gov.it"
        assert _registrable_domain("www.example.com.mx") == "example.com.mx"
        assert _registrable_domain("phish.example.co.in") == "example.co.in"


class TestNetworkIsolation:
    """Verifica che tldextract NON faccia richieste di rete."""

    def test_tldextract_never_fetches_urls(self):
        """L'estrattore è configurato con suffix_list_urls=None → zero rete."""
        from graph_engine.lexical import typosquat as ts

        # L'estrattore deve esistere ed essere un TLDExtract
        assert ts._extractor is not None
        # suffix_list_urls deve essere una tupla vuota (None → ())
        assert ts._extractor.suffix_list_urls == ()

    def test_extract_works_offline(self):
        """Verifica che l'estrazione funzioni senza alcuna richiesta di rete.

        Blocca ESPLICITAMENTE ``requests.Session.send`` — il punto di
        strozzatura unico della libreria ``requests`` usata da tldextract.
        Se una versione futura di tldextract tentasse una richiesta HTTP
        (es. per un cambiamento nel comportamento offline), questo test
        fallisce rumorosamente con ``RuntimeError`` invece di passare
        silenziosamente per assenza di rete.
        """

        def _blocked(self_or_cls, request, **kwargs):
            raise RuntimeError(
                "RETE BLOCCATA: tldextract ha tentato una richiesta HTTP "
                f"({request.method} {request.url})! "
                "Verificare la configurazione offline di TLDExtract."
            )

        with patch.object(requests.Session, "send", _blocked):
            cases = [
                ("login.inps.gov.it", "inps.gov.it"),
                ("evil.example.com", "example.com"),
                ("phish.example.co.uk", "example.co.uk"),
                ("www.example.com.mx", "example.com.mx"),
                ("sub.example.co.in", "example.co.in"),
                ("keyimportacao.com.br", "keyimportacao.com.br"),
                ("cittadino.inps.it", "inps.it"),
            ]
            for hostname, expected in cases:
                assert _registrable_domain(hostname) == expected, (
                    f"Failed: _registrable_domain({hostname!r})"
                    f" should be {expected!r}"
                )


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
