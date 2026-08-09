"""Tests for domain model instantiation."""

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


# ---------------------------------------------------------------------------
# TransitionKind
# ---------------------------------------------------------------------------


def test_transition_kind_has_nine_values():
    assert len(TransitionKind) == 9


# ---------------------------------------------------------------------------
# AnalysisTarget
# ---------------------------------------------------------------------------


def test_analysis_target_defaults():
    target = AnalysisTarget(input_url="https://example.com")
    assert isinstance(target.id, uuid.UUID)
    assert target.input_url == "https://example.com"
    assert target.canonical_url is None
    assert target.url_hash is None
    assert target.status == TargetStatus.queued
    assert target.root_state_id is None
    assert isinstance(target.created_at, datetime)


def test_analysis_target_explicit():
    root_id = uuid.uuid4()
    target = AnalysisTarget(
        input_url="https://evil.example/login",
        canonical_url="https://evil.example/login",
        url_hash="abc123",
        status=TargetStatus.running,
        root_state_id=root_id,
    )
    assert target.canonical_url == "https://evil.example/login"
    assert target.url_hash == "abc123"
    assert target.status == TargetStatus.running
    assert target.root_state_id == root_id


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


def test_state_instantiation():
    state = State(
        target_id=uuid.uuid4(),
        url="https://evil.example/page1",
        dom_hash="abcdef",
        depth=2,
    )
    assert isinstance(state.id, uuid.UUID)
    assert state.depth == 2
    assert state.screenshot_ref is None
    assert state.har_ref is None


def test_state_default_depth():
    state = State(
        target_id=uuid.uuid4(),
        url="https://evil.example/page1",
        dom_hash="abcdef",
    )
    assert state.depth == 0


# ---------------------------------------------------------------------------
# Transition
# ---------------------------------------------------------------------------


def test_transition_instantiation():
    t = Transition(
        target_id=uuid.uuid4(),
        from_state=uuid.uuid4(),
        to_state=uuid.uuid4(),
        kind=TransitionKind.click,
        trigger={"selector": "#btn-login", "coords": [100, 200]},
    )
    assert isinstance(t.id, uuid.UUID)
    assert t.kind == TransitionKind.click
    assert t.trigger["selector"] == "#btn-login"
    assert isinstance(t.ts, datetime)


def test_transition_trigger_default():
    t = Transition(
        target_id=uuid.uuid4(),
        from_state=uuid.uuid4(),
        to_state=uuid.uuid4(),
        kind=TransitionKind.http_3xx,
    )
    assert t.trigger is None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_evidence_instantiation():
    ev = Evidence(
        target_id=uuid.uuid4(),
        scope=EvidenceScope.state,
        scope_id=uuid.uuid4(),
        layer="L3",
        key="form_action",
        value="/submit",
        weight=0.8,
        produced_by="heuristic_form_detector",
    )
    assert isinstance(ev.id, uuid.UUID)
    assert ev.scope == EvidenceScope.state
    assert ev.layer == "L3"
    assert ev.weight == 0.8
    assert isinstance(ev.ts, datetime)


def test_evidence_default_weight():
    ev = Evidence(
        target_id=uuid.uuid4(),
        scope=EvidenceScope.target,
        scope_id=uuid.uuid4(),
        layer="L0",
        key="url_length",
        value="512",
        produced_by="static_analyzer",
    )
    assert ev.weight == 1.0


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def test_verdict_instantiation():
    v = Verdict(
        target_id=uuid.uuid4(),
        classification=Classification.phishing,
        confidence=0.95,
        brand="Microsoft",
        kit_family="EvilGinx2",
        rationale="Brand impersonation + exfil endpoint detected",
        final_url="https://evil.example/collect",
        exfil_endpoint="https://evil.example/api/submit",
    )
    assert v.classification == Classification.phishing
    assert v.confidence == 0.95
    assert v.brand == "Microsoft"
    assert v.kit_family == "EvilGinx2"


def test_verdict_minimal():
    v = Verdict(
        target_id=uuid.uuid4(),
        classification=Classification.benign,
    )
    assert v.confidence == 0.0
    assert v.brand is None


def test_classification_enum_values():
    assert Classification.benign.value == "benign"
    assert Classification.suspicious.value == "suspicious"
    assert Classification.phishing.value == "phishing"
    assert Classification.aitm.value == "aitm"
