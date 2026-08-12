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
    """Test di build_signature con vari input."""

    def test_signature_with_typosquat_evidence(self):
        """Evidence typosquat con brand → 'Phishing: X Impersonation'."""
        verdict = _verdict()
        evidence = [
            {"key": "typosquat", "value": '{"brand": "Poste Italiane", "matched_domain": "poste-it.com", "distance": 1}'},
        ]
        sig = build_signature(verdict, evidence)
        assert "Poste Italiane" in sig
        assert "Impersonation" in sig

    def test_signature_with_verdict_brand(self):
        """Verdict.brand valorizzato → brand impersonation."""
        verdict = _verdict(brand="PayPal")
        sig = build_signature(verdict, [])
        assert "PayPal" in sig
        assert "Impersonation" in sig

    def test_signature_gate_solved(self):
        """Evidence con gate_solved → 'Suspicious Gate Bypass'."""
        verdict = _verdict()
        evidence = [{"key": "gate_solved", "value": "cloudflare_turnstile"}]
        sig = build_signature(verdict, evidence)
        assert "Gate Bypass" in sig

    def test_signature_credential_harvesting(self):
        """Evidence aitm_email_payload → 'Credential Harvesting'."""
        verdict = _verdict()
        evidence = [
            {"key": "aitm_email_payload", "value": "user@example.com"},
        ]
        sig = build_signature(verdict, evidence)
        assert "Credential Harvesting" in sig

    def test_signature_generic_phishing(self):
        """Nessun segnale specifico → 'Phishing Page Detected'."""
        verdict = _verdict(confidence=0.88)
        sig = build_signature(verdict, [])
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

    def test_timed_out_forces_safe_allow(self):
        """timed_out=True → safe/allow con reason onesto."""
        resp = build_trellix_response(None, timed_out=True)
        assert resp["verdict"] == "safe"
        assert resp["recommended_action"] == "allow"
        assert "Analysis-Incomplete" in resp["signature"]
        assert resp["reason"]  # non vuoto
        assert "analisi non è terminata" in resp["reason"].lower()

    def test_none_data_returns_incomplete(self):
        """data=None → safe/allow/0.1."""
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
