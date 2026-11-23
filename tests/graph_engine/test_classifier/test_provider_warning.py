"""Pagine d'avviso dei provider → verdetto malevolo deterministico."""

from __future__ import annotations

import uuid

from graph_engine.api.verdict_response import build_signature, build_verdict_response
from graph_engine.classifier.prefilter import prefilter
from graph_engine.classifier.provider_warning import detect_provider_warning
from graph_engine.models import AnalysisTarget, Classification, TargetStatus, Verdict


def _bundle(states, input_url="https://kit.pages.dev/") -> dict:
    return {
        "target_id": str(uuid.uuid4()),
        "input_url": input_url,
        "canonical_url": input_url,
        "num_states": len(states),
        "states": states,
        "flags": {},
        "evidence_summary": {},
        "transition_kinds_seen": {},
    }


def _state(url, title="", text="", depth=0, ocr=""):
    return {"url": url, "title": title, "visible_text": text,
            "ocr_text": ocr, "depth": depth, "form_fields": []}


# Testo osservato nel test reale (pages.dev, 2026-11-19).
_CF_MALWARE = _state(
    "https://kit.pages.dev/",
    title="Suspected Malware | Cloudflare",
    text="Warning This website has been reported for potentially "
         "distributing malware. Cloudflare Ray ID: 8f3a",
)


class TestDetection:
    def test_cloudflare_malware_interstitial(self):
        w = detect_provider_warning(_bundle([_CF_MALWARE]))
        assert w["provider"] == "Cloudflare" and w["kind"] == "malware"

    def test_cloudflare_phishing_from_text_only(self):
        s = _state("https://kit.pages.dev/", title="Warning",
                   text="This website has been reported for potentially phishing. "
                        "Performance & security by Cloudflare")
        w = detect_provider_warning(_bundle([s]))
        assert w["provider"] == "Cloudflare" and w["kind"] == "phishing"

    def test_safe_browsing_interstitial_via_ocr(self):
        s = _state("https://kit.pages.dev/", ocr="Deceptive site ahead Attackers on ...")
        w = detect_provider_warning(_bundle([s]))
        assert w["provider"] == "Google Safe Browsing" and w["kind"] == "phishing"

    def test_article_about_phishing_is_not_a_warning(self):
        s = _state("https://blog.example/", title="How to spot phishing",
                   text="Suspected phishing emails often impersonate banks. "
                        "Cloudflare and others publish guidance.",
                   ) | {"title": "How to spot phishing"}
        assert detect_provider_warning(_bundle([s], "https://blog.example/")) is None

    def test_warning_on_third_party_site_is_ignored(self):
        """Un avviso su un sito terzo raggiunto con un click non dice
        nulla sul dominio analizzato."""
        root = _state("https://legit.example/", title="Home", text="Welcome")
        other = dict(_CF_MALWARE, url="https://elsewhere.example/", depth=1)
        assert detect_provider_warning(_bundle([root, other], "https://legit.example/")) is None


class TestPrefilterRule:
    def test_warning_decides_phishing_without_model(self):
        verdict = prefilter(_bundle([_CF_MALWARE]))
        assert verdict is not None
        assert verdict.classification == Classification.phishing
        assert verdict.confidence == 0.9
        assert verdict.produced_by == "prefilter"
        assert verdict.kit_family == "provider-warning:Cloudflare:malware"
        assert "Cloudflare" in verdict.rationale

    def test_rule_wins_over_strong_signal_delegation(self):
        bundle = _bundle([_CF_MALWARE])
        bundle["passive_risk_score"] = 0.9  # normalmente → delega a Foundry
        assert prefilter(bundle) is not None


class TestExternalResponse:
    def test_signature_names_the_provider(self):
        target = AnalysisTarget(input_url="https://kit.pages.dev/", status=TargetStatus.done)
        verdict = Verdict(
            target_id=target.id, classification=Classification.phishing,
            confidence=0.9, produced_by="prefilter",
            kit_family="provider-warning:Cloudflare:malware",
            rationale="avviso Cloudflare",
        )
        body = build_verdict_response(
            {"target": target, "verdict": verdict, "evidence": [], "states": [], "transitions": []}
        )
        assert body["result"]["verdict"] == "malicious"
        assert body["result"]["recommended_action"] == "block"
        assert body["result"]["signature"] == "Flagged by Cloudflare: Suspected Malware"

    def test_signature_unchanged_for_other_verdicts(self):
        verdict = Verdict(target_id=uuid.uuid4(), classification=Classification.phishing,
                          confidence=0.9, produced_by="foundry", brand="PayPal")
        assert build_signature(verdict, [], mapped="malicious") == "Phishing: PayPal Impersonation"


class TestMalwareDownloadSignature:
    def test_malware_download_lure_has_dedicated_signature(self):
        verdict = Verdict(target_id=uuid.uuid4(), classification=Classification.phishing,
                          confidence=0.9, produced_by="foundry",
                          brand="Adobe", kit_family="malware-download")
        assert build_signature(verdict, [], mapped="malicious") == (
            "Malware Download Lure: Adobe Impersonation"
        )

    def test_without_brand_generic_signature(self):
        verdict = Verdict(target_id=uuid.uuid4(), classification=Classification.phishing,
                          confidence=0.9, produced_by="foundry", kit_family="malware-download")
        assert build_signature(verdict, [], mapped="malicious") == "Malware Download Lure"

    def test_prompt_contains_malware_lure_rule(self):
        from graph_engine.classifier.foundry_classifier import _load_system_prompt

        prompt = _load_system_prompt()
        assert "Malware delivery lures" in prompt
        assert '"kit_family": "malware-download"' in prompt
