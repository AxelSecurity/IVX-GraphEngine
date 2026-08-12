"""Test roundtrip salva/carica con tutti i campi."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    TransitionKind,
    Verdict,
)
from graph_engine.storage.repository import get_target_by_id, save_target


def _make_full_graph() -> tuple[
    AnalysisTarget, list[State], list[Transition], list[Evidence], Verdict
]:
    """Costruisce un grafo completo per il test roundtrip."""
    tid = uuid.uuid4()
    now = datetime(2026, 8, 12, 10, 0, 0, tzinfo=timezone.utc)

    target = AnalysisTarget(
        id=tid,
        input_url="https://evil.example.com/login",
        canonical_url="https://evil.example.com/login",
        url_hash="abc123hash",
        final_url="https://evil.example.com/pay",
        status=TargetStatus.done,
        root_state_id=None,
        created_at=now,
    )

    s1 = State(
        id=uuid.uuid4(),
        target_id=tid,
        url="https://evil.example.com/login",
        dom_hash="domhash1",
        depth=0,
        screenshot_ref="data/artifacts/s1/screenshot.png",
        har_ref="data/artifacts/s1/snapshot.har",
    )
    s2 = State(
        id=uuid.uuid4(),
        target_id=tid,
        url="https://evil.example.com/pay",
        dom_hash="domhash2",
        depth=1,
        screenshot_ref=None,
        har_ref=None,
    )

    t1 = Transition(
        id=uuid.uuid4(),
        target_id=tid,
        from_state=s1.id,
        to_state=s2.id,
        kind=TransitionKind.click,
        trigger={"selector": "#submit", "text": "Continue"},
        ts=now,
    )

    e1 = Evidence(
        id=uuid.uuid4(),
        target_id=tid,
        scope=EvidenceScope.state,
        scope_id=s1.id,
        layer="L2",
        key="domain_age_days",
        value="5",
        weight=0.35,
        produced_by="osint.rdap",
        ts=now,
    )

    verdict = Verdict(
        target_id=tid,
        classification=Classification.phishing,
        confidence=0.92,
        produced_by="foundry",
        brand="ExampleBank",
        kit_family="Typhoon v2",
        rationale="Form con credenziali + redirect a dominio sospetto",
        final_url="https://evil.example.com/pay",
        exfil_endpoint="https://evil.example.com/exfil",
    )

    return target, [s1, s2], [t1], [e1], verdict


class TestSaveAndLoad:
    async def test_roundtrip_all_fields(self, tmp_path):
        """save_target() → get_target_by_id() ritorna dati equivalenti."""
        db = str(tmp_path / "test.db")
        target, states, transitions, evidence, verdict = _make_full_graph()
        s1, s2 = states

        await save_target(target, states, transitions, evidence, verdict, db_path=db)

        result = await get_target_by_id(str(target.id), db_path=db)
        assert result is not None, "get_target_by_id ha restituito None"

        # ── Target ──────────────────────────────────────────────────────
        loaded_target = result["target"]
        assert isinstance(loaded_target, AnalysisTarget)
        assert loaded_target.id == target.id
        assert loaded_target.input_url == target.input_url
        assert loaded_target.canonical_url == target.canonical_url
        assert loaded_target.url_hash == target.url_hash
        assert loaded_target.final_url == target.final_url
        assert loaded_target.status == TargetStatus.done
        assert loaded_target.created_at == target.created_at

        # ── States ──────────────────────────────────────────────────────
        assert len(result["states"]) == 2
        assert isinstance(result["states"][0], State)
        loaded_s1 = result["states"][0]
        assert loaded_s1.url == s1.url
        assert loaded_s1.dom_hash == s1.dom_hash
        assert loaded_s1.depth == s1.depth
        assert loaded_s1.screenshot_ref == s1.screenshot_ref
        assert loaded_s1.har_ref == s1.har_ref

        loaded_s2 = result["states"][1]
        assert loaded_s2.url == s2.url
        assert loaded_s2.screenshot_ref is None

        # ── Transitions ─────────────────────────────────────────────────
        assert len(result["transitions"]) == 1
        assert isinstance(result["transitions"][0], Transition)
        loaded_t = result["transitions"][0]
        assert loaded_t.kind == TransitionKind.click
        assert loaded_t.trigger == {"selector": "#submit", "text": "Continue"}

        # ── Evidence ────────────────────────────────────────────────────
        assert len(result["evidence"]) == 1
        assert isinstance(result["evidence"][0], Evidence)
        loaded_e = result["evidence"][0]
        assert loaded_e.key == "domain_age_days"
        assert loaded_e.value == "5"
        assert loaded_e.weight == 0.35

        # ── Verdict ─────────────────────────────────────────────────────
        assert result["verdict"] is not None
        assert isinstance(result["verdict"], Verdict)
        loaded_v = result["verdict"]
        assert loaded_v.classification == Classification.phishing
        assert loaded_v.confidence == 0.92
        assert loaded_v.brand == "ExampleBank"
        assert loaded_v.kit_family == "Typhoon v2"
        assert loaded_v.rationale != ""
        assert loaded_v.final_url == "https://evil.example.com/pay"
        assert loaded_v.exfil_endpoint == "https://evil.example.com/exfil"

    async def test_verdict_none_handled(self, tmp_path):
        """Salvataggio senza verdict → caricamento con verdict=None."""
        db = str(tmp_path / "test.db")
        target, states, transitions, evidence, _ = _make_full_graph()

        await save_target(target, states, transitions, evidence, None, db_path=db)
        result = await get_target_by_id(str(target.id), db_path=db)

        assert result is not None
        assert result["verdict"] is None

    async def test_nonexistent_id_returns_none(self, tmp_path):
        """ID inesistente → None."""
        db = str(tmp_path / "test.db")
        result = await get_target_by_id(str(uuid.uuid4()), db_path=db)
        assert result is None
