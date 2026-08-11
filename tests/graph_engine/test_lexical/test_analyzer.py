"""Integration tests for the L1 analyzer orchestrator."""

from __future__ import annotations

from graph_engine.lexical.analyzer import analyze


class TestAnalyzerIntegration:
    def test_clean_url_produces_no_or_few_evidence(self):
        """Un URL pulito (brand noto, hosting normale) produce zero o pochi segnali."""
        result = analyze("https://www.google.com/search", [])
        # Google.com non è typosquat, non è DGA, non è IP, non è mixed-script,
        # non ha email payload → al massimo dga_borderline (weight=0.0)
        significant = [e for e in result["evidence"] if e.get("weight", 0) > 0]
        assert len(significant) == 0
        assert result["lexical_risk_score"] == 0.0

    def test_typosquat_signal_produces_evidence(self):
        """Un dominio typosquat genera evidenza con weight > 0."""
        # "inpx.it" vs "inps.it" — 1 char distance
        result = analyze("https://inpx.it/login", [])
        typosquat_ev = [e for e in result["evidence"] if e["key"] == "typosquat"]
        assert len(typosquat_ev) == 1
        assert typosquat_ev[0]["weight"] > 0
        assert result["lexical_risk_score"] > 0

    def test_aitm_email_signal(self):
        """Payload email nidificato → segnale AiTM con weight 0.40."""
        result = analyze(
            "https://evil.example/login",
            [{"kind": "email", "decoded": "victim@company.example"}],
        )
        aitm_ev = [e for e in result["evidence"] if e["key"] == "aitm_email_payload"]
        assert len(aitm_ev) == 1
        assert aitm_ev[0]["weight"] == 0.40
        assert result["lexical_risk_score"] >= 0.40

    def test_aitm_email_signal_only_with_email_kind(self):
        """Solo payload con kind='email' attivano il segnale AiTM."""
        result = analyze(
            "https://evil.example/login",
            [
                {"kind": "url", "decoded": "https://evil.example/c2"},
                {"kind": "unknown", "decoded": "some data"},
            ],
        )
        aitm_ev = [e for e in result["evidence"] if e["key"] == "aitm_email_payload"]
        assert len(aitm_ev) == 0

    def test_multiple_signals_increase_risk(self):
        """Più segnali contemporaneamente → rischio più alto."""
        # Typosquat + abuse-prone infra → risk > typosquat alone
        result_single = analyze("https://inpx.it/login", [])
        result_multi = analyze(
            "https://inpx.workers.dev/login",
            [{"kind": "email", "decoded": "victim@corp.example"}],
        )
        assert result_multi["lexical_risk_score"] > result_single["lexical_risk_score"]

    def test_risk_score_clamped_to_one(self):
        """Il rischio non supera mai 1.0."""
        result = analyze(
            "https://evil.workers.dev/login",
            [
                {"kind": "email", "decoded": "v1@c.example"},
                {"kind": "email", "decoded": "v2@c.example"},
            ],
        )
        assert result["lexical_risk_score"] <= 1.0

    def test_evidence_has_required_fields(self):
        """Ogni entry evidence ha i campi necessari per costruire Evidence()."""
        result = analyze("https://evil.example/login", [])
        for ev in result["evidence"]:
            assert "scope" in ev
            assert "layer" in ev
            assert ev["layer"] == "L1"
            assert "key" in ev
            assert "value" in ev
            assert "weight" in ev
            assert "produced_by" in ev
            assert ev["produced_by"] == "lexical"
            assert "ts" in ev
