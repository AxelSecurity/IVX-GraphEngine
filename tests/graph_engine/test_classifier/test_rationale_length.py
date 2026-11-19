"""Motivazione sintetica: prompt e tetto di sicurezza lato codice."""

from __future__ import annotations

from graph_engine.classifier import foundry_classifier as fc


class TestCapRationale:
    def test_short_text_unchanged_and_whitespace_normalised(self):
        assert fc._cap_rationale("  Phishing   Microsoft:\n campi email ") == (
            "Phishing Microsoft: campi email"
        )

    def test_long_text_cut_on_word_with_ellipsis(self):
        text = "parola " * 200
        capped = fc._cap_rationale(text)
        assert len(capped) <= fc._MAX_RATIONALE_CHARS
        assert capped.endswith("…")
        assert not capped[:-1].endswith(" ")

    def test_empty_or_non_string_is_none(self):
        assert fc._cap_rationale("") is None
        assert fc._cap_rationale("   ") is None
        assert fc._cap_rationale(None) is None
        assert fc._cap_rationale(123) is None


class TestPromptAsksForBrevity:
    def test_prompt_sets_length_and_bans_report_style(self):
        prompt = fc._load_system_prompt()
        assert "350 characters" in prompt
        assert "2-3 sentences" in prompt
        assert "Do NOT list counts, flags" in prompt
