"""Test per trellix_verdict: mapping, firma, risposta."""

from __future__ import annotations

import uuid

from graph_engine.api.trellix_verdict import (
    VERDICT_MAP,
    build_signature,
    build_trellix_response,
    entry_response,
)
from graph_engine.models import Classification, Verdict


def _verdict(**kwargs) -> Verdict:
    """Verdict con target_id UUID valido."""
    defaults = dict(
        target_id=uuid.uuid4(),
        classification=Classification.phishing,
        confidence=0.9,
        produced_by="foundry",
    )
    defaults.update(kwargs)
    return Verdict(**defaults)


class TestVerdictMapping:
    """Test del mapping Classification → safe/malicious."""

    def test_benign_maps_to_safe(self):
        assert VERDICT_MAP[Classification.benign] == "safe"

    def test_suspicious_maps_to_safe(self):
        """In dubbio → safe (mai bloccare su incertezza)."""
        assert VERDICT_MAP[Classification.suspicious] == "safe"

    def test_phishing_maps_to_malicious(self):
        assert VERDICT_MAP[Classification.phishing] == "malicious"


class TestBuildSignature:
    """Test di build_signature con vari input.

    Le firme specifiche (brand impersonation, gate bypass, credential
    harvesting) descrivono un ATTACCO: vengono cercate SOLO con
    ``mapped="malicious"``.  Regressione del collaudo Docker (2026-08-27):
    example.org classificato benign con ``verdict.brand="IANA"``
    valorizzato da Foundry produceva una firma "Phishing: IANA
    Impersonation" su un verdetto ``safe``, contraddittoria per il
    consumatore.
    """

    def test_signature_with_typosquat_evidence(self):
        """Evidence typosquat con brand → 'Phishing: X Impersonation'."""
        verdict = _verdict()
        evidence = [
            {"key": "typosquat", "value": '{"brand": "Poste Italiane", "matched_domain": "poste-it.com", "distance": 1}'},
        ]
        sig = build_signature(verdict, evidence, mapped="malicious")
        assert "Poste Italiane" in sig
        assert "Impersonation" in sig

    def test_signature_with_verdict_brand(self):
        """Verdict.brand valorizzato → brand impersonation."""
        verdict = _verdict(brand="PayPal")
        sig = build_signature(verdict, [], mapped="malicious")
        assert "PayPal" in sig
        assert "Impersonation" in sig

    def test_signature_gate_solved(self):
        """Evidence con gate_solved → 'Suspicious Gate Bypass'."""
        verdict = _verdict()
        evidence = [{"key": "gate_solved", "value": "cloudflare_turnstile"}]
        sig = build_signature(verdict, evidence, mapped="malicious")
        assert "Gate Bypass" in sig

    def test_signature_credential_harvesting(self):
        """Evidence aitm_email_payload → 'Credential Harvesting'."""
        verdict = _verdict()
        evidence = [
            {"key": "aitm_email_payload", "value": "user@example.com"},
        ]
        sig = build_signature(verdict, evidence, mapped="malicious")
        assert "Credential Harvesting" in sig

    def test_brand_not_used_when_safe(self):
        """Regressione: benign con brand valorizzato → firma generica,
        MAI 'Phishing: X Impersonation' su un verdetto safe."""
        verdict = _verdict(
            classification=Classification.benign,
            confidence=0.95,
            brand="IANA",
        )
        sig = build_signature(verdict, [], mapped="safe")
        assert sig == "No Threats Detected"
        assert "Phishing" not in sig

    def test_attack_signatures_not_used_when_safe(self):
        """Regressione: gate/credential su verdetto safe → firma generica."""
        verdict = _verdict(
            classification=Classification.benign,
            confidence=0.95,
        )
        evidence = [
            {"key": "gate_solved", "value": "cloudflare_turnstile"},
            {"key": "aitm_email_payload", "value": "user@example.com"},
        ]
        sig = build_signature(verdict, evidence, mapped="safe")
        assert sig == "No Threats Detected"
        assert "Gate" not in sig
        assert "Credential" not in sig

    def test_signature_generic_phishing(self):
        """Nessun segnale specifico → 'Phishing Page Detected'."""
        verdict = _verdict(confidence=0.88)
        sig = build_signature(verdict, [], mapped="malicious")
        assert "Phishing" in sig

    def test_signature_generic_benign(self):
        """Nessun segnale, benign → 'No Threats Detected'."""
        verdict = _verdict(
            classification=Classification.benign,
            confidence=0.95,
        )
        sig = build_signature(verdict, [])
        assert "No Threats" in sig


class TestBuildTrellixResponse:
    """Test di build_trellix_response."""

    def test_none_data_returns_incomplete(self):
        """data=None → safe/allow/0.1.

        Ramo DIFENSIVO (nessuna analisi presente su SQLite): la route
        attende sempre il completamento reale, quindi questo ramo non
        è più raggiungibile dal path principale — resta come rete di
        sicurezza."""
        resp = build_trellix_response(None)
        assert resp["verdict"] == "safe"
        assert resp["confidence"] == 0.1
        assert "Analysis-Incomplete" in resp["signature"]

    def test_error_status_returns_failed(self):
        """Status error → Analysis-Failed con dettaglio."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://bad.example",
            status=TargetStatus.error,
        )
        evidence = [
            {
                "key": "pipeline_error",
                "value": "RuntimeError: something broke",
            },
        ]
        resp = build_trellix_response(
            {"target": target, "verdict": None, "evidence": evidence},
        )
        assert resp["verdict"] == "safe"
        assert "Analysis-Failed" in resp["signature"]
        assert "something broke" in resp["reason"]

    def test_done_without_verdict_returns_incomplete(self):
        """Status done ma nessun verdict → safe/0.1."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://ok.example",
            status=TargetStatus.done,
        )
        resp = build_trellix_response(
            {"target": target, "verdict": None, "evidence": []},
        )
        assert resp["verdict"] == "safe"
        assert "classificazione assente" in resp["reason"].lower()

    def test_benign_with_brand_has_coherent_signature(self):
        """Regressione end-to-end del caso reale (example.org/IANA):
        benign + brand valorizzato → verdict safe, firma benigna."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://example.org/",
            status=TargetStatus.done,
        )
        verdict = _verdict(
            classification=Classification.benign,
            confidence=0.95,
            brand="IANA",
        )
        resp = build_trellix_response(
            {"target": target, "verdict": verdict, "evidence": []},
        )
        assert resp["verdict"] == "safe"
        assert resp["confidence"] == 0.95
        assert resp["signature"] == "No Threats Detected"
        assert "Phishing" not in resp["signature"]
        assert resp["recommended_action"] == "allow"

    def test_phishing_with_brand_keeps_impersonation_signature(self):
        """Invariante: phishing + brand → malicious + firma impersonation."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://phish.example/",
            status=TargetStatus.done,
        )
        verdict = _verdict(brand="Netflix")
        resp = build_trellix_response(
            {"target": target, "verdict": verdict, "evidence": []},
        )
        assert resp["verdict"] == "malicious"
        assert resp["signature"] == "Phishing: Netflix Impersonation"
        assert resp["recommended_action"] == "block"


class TestSuspiciousBlockThreshold:
    """Blocco dei sospetti forti: suspicious con confidenza ≥ 0.6
    (segnali deterministici misurati) → malicious/block.  Sotto soglia
    resta il comportamento storico (safe/allow, confidenza cappata)."""

    def test_strong_suspicious_maps_to_malicious_block(self):
        """suspicious 0.6 → malicious/block con firma dedicata."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://ledger-com-login.pages.dev/",
            status=TargetStatus.done,
        )
        verdict = _verdict(
            classification=Classification.suspicious,
            confidence=0.6,
        )
        resp = build_trellix_response(
            {"target": target, "verdict": verdict, "evidence": []},
        )
        assert resp["verdict"] == "malicious"
        assert resp["recommended_action"] == "block"
        assert resp["confidence"] >= 0.8
        assert resp["signature"] == "Suspicious Site Blocked"

    def test_weak_suspicious_stays_safe_allow(self):
        """Dubbio debole (0.15, 0.4, 0.59) → safe/allow come da policy."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://doubt.example/",
            status=TargetStatus.done,
        )
        for conf in (0.15, 0.4, 0.59):
            verdict = _verdict(
                classification=Classification.suspicious,
                confidence=conf,
            )
            resp = build_trellix_response(
                {"target": target, "verdict": verdict, "evidence": []},
            )
            assert resp["verdict"] == "safe", f"conf={conf}"
            assert resp["recommended_action"] == "allow", f"conf={conf}"
            assert resp["confidence"] <= 0.5, f"conf={conf}"
            assert (
                resp["signature"] == "Suspicious Site (Low Confidence)"
            ), f"conf={conf}"

    def test_strong_suspicious_with_brand_keeps_impersonation(self):
        """Blocco da soglia + brand → vince la firma d'attacco specifica."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://ledger-com-login.pages.dev/",
            status=TargetStatus.done,
        )
        verdict = _verdict(
            classification=Classification.suspicious,
            confidence=0.6,
            brand="Ledger",
        )
        resp = build_trellix_response(
            {"target": target, "verdict": verdict, "evidence": []},
        )
        assert resp["verdict"] == "malicious"
        assert resp["signature"] == "Phishing: Ledger Impersonation"

    def test_boundary_just_below_threshold_allows(self):
        """0.5999 resta sotto soglia: il confine è ≥ 0.6."""
        from graph_engine.models import AnalysisTarget, TargetStatus

        target = AnalysisTarget(
            input_url="https://border.example/",
            status=TargetStatus.done,
        )
        verdict = _verdict(
            classification=Classification.suspicious,
            confidence=0.5999,
        )
        resp = build_trellix_response(
            {"target": target, "verdict": verdict, "evidence": []},
        )
        assert resp["verdict"] == "safe"
        assert resp["recommended_action"] == "allow"


class TestEntryResponse:
    """Test di entry_response per allowlist/blacklist hit."""

    def test_whitelist_entry(self):
        resp = entry_response({"list_type": "whitelist", "note": "Trusted"})
        assert resp["verdict"] == "safe"
        assert resp["confidence"] == 1.0
        assert resp["recommended_action"] == "allow"
        assert "Trusted" in resp["reason"]

    def test_blacklist_entry(self):
        resp = entry_response({"list_type": "blacklist", "note": "Known phish"})
        assert resp["verdict"] == "malicious"
        assert resp["confidence"] == 1.0
        assert resp["recommended_action"] == "block"
        assert "Known phish" in resp["reason"]
