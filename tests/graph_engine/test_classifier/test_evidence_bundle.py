"""Tests for evidence_bundle — build + serialize, must stay compact."""

from __future__ import annotations

import uuid

import pytest

from graph_engine.classifier.evidence_bundle import (
    build_evidence_bundle,
    bundle_to_prompt_text,
)
from graph_engine.models import (
    Evidence,
    EvidenceScope,
    State,
    Transition,
    TransitionKind,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state(dom_hash: str, depth: int, url: str = "") -> State:
    return State(
        target_id=uuid.uuid4(),
        url=url or f"https://example.com/page?d={depth}",
        dom_hash=dom_hash,
        depth=depth,
    )


def _transition(
    from_state: uuid.UUID,
    to_state: uuid.UUID,
    kind: TransitionKind,
) -> Transition:
    return Transition(
        target_id=uuid.uuid4(),
        from_state=from_state,
        to_state=to_state,
        kind=kind,
    )


def _evidence(key: str, value: str = "test") -> Evidence:
    return Evidence(
        target_id=uuid.uuid4(),
        scope=EvidenceScope.target,
        scope_id=uuid.uuid4(),
        layer="L4",
        key=key,
        value=value,
        produced_by="test",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildEvidenceBundle:
    """build_evidence_bundle must produce a compact dict with no raw DOM."""

    def test_basic_structure(self):
        s0 = _state("aaa", 0)
        s1 = _state("bbb", 1)
        transitions = [_transition(s0.id, s1.id, TransitionKind.http_3xx)]
        evidence = [_evidence("blocked_by_gate", "cloudflare_turnstile")]

        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url="https://example.com/landing",
            states=[s0, s1],
            transitions=transitions,
            evidence=evidence,
            leaf_form_fields={str(s1.id): []},
            leaf_visible_text={str(s1.id): "Welcome to the site"},
            leaf_titles={str(s1.id): "Landing Page"},
        )

        # Basics
        assert bundle["input_url"] == "https://example.com"
        assert bundle["canonical_url"] == "https://example.com/landing"
        assert bundle["num_states"] == 2
        assert bundle["num_transitions"] == 1
        assert bundle["max_depth_reached"] == 1

        # Transition-kind counts
        assert bundle["transition_kinds_seen"] == {"http_3xx": 1}

        # Flags
        assert bundle["flags"]["had_gate"] is True
        assert bundle["flags"]["had_navigation_error"] is False
        assert bundle["flags"]["had_replay_fallback"] is False
        assert bundle["flags"]["had_unhandled_error"] is False

        # Evidence summary
        assert bundle["evidence_summary"]["blocked_by_gate"] == 1

        # Leaf states
        assert len(bundle["leaf_states"]) == 1  # s1 is the only leaf
        leaf = bundle["leaf_states"][0]
        assert leaf["url"] == s1.url
        assert leaf["title"] == "Landing Page"
        assert leaf["visible_text"] == "Welcome to the site"

    def test_no_dom_raw_content_leaked(self):
        """Bundle must NOT contain any raw HTML/script tags accidentally."""
        s0 = _state("aaa", 0)
        # Add a leaf with visible text that looks like HTML
        leaf_text = "<script>alert(1)</script><p>Visible only</p>"

        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0],
            transitions=[],
            evidence=[],
            leaf_form_fields={str(s0.id): []},
            leaf_visible_text={str(s0.id): leaf_text},
            leaf_titles={str(s0.id): "Test"},
        )

        serialized = bundle_to_prompt_text(bundle)
        # The bundle_to_prompt_text dutifully includes what we gave it.
        # The responsibility for stripping tags lies with the caller
        # (_extract_visible_text in cli.py).  But the bundle dict
        # itself must not accidentally leak DOM strings in its own keys.
        for key in bundle:
            assert "dom" not in key.lower(), f"Suspicious key: {key}"
            assert "html" not in key.lower(), f"Suspicious key: {key}"

        # The leaf_states must NOT carry screenshot bytes or HAR blobs
        for leaf in bundle.get("leaf_states", []):
            assert "screenshot" not in leaf, "Raw screenshot in bundle"
            assert "har" not in leaf, "Raw HAR in bundle"
            assert "dom_html" not in leaf, "Raw DOM in bundle"

    def test_flags_false_when_no_evidence(self):
        """All flags must be False when no Evidence entries exist."""
        s0 = _state("aaa", 0)

        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0],
            transitions=[],
            evidence=[],
            leaf_form_fields={},
            leaf_visible_text={},
            leaf_titles={},
        )

        flags = bundle["flags"]
        for name, value in flags.items():
            assert value is False, f"Flag {name} must be False; got {value}"

    def test_multiple_evidence_keys(self):
        s0 = _state("aaa", 0)
        evidence = [
            _evidence("blocked_by_gate", "cloudflare"),
            _evidence("navigation_error", "timeout"),
            _evidence("replay_fallback_used", "goto failed"),
        ]

        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0],
            transitions=[],
            evidence=evidence,
            leaf_form_fields={},
            leaf_visible_text={},
            leaf_titles={},
        )

        flags = bundle["flags"]
        assert flags["had_gate"] is True
        assert flags["had_navigation_error"] is True
        assert flags["had_replay_fallback"] is True
        assert flags["had_unhandled_error"] is False


class TestBundleToPromptText:
    """bundle_to_prompt_text must produce readable structured text."""

    def test_output_is_text_not_json(self):
        """Output is human-readable labeled sections, not raw JSON."""
        s0 = _state("aaa", 0, "https://example.com")
        s1 = _state("bbb", 1, "https://example.com/step2")

        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0, s1],
            transitions=[
                _transition(s0.id, s1.id, TransitionKind.click),
            ],
            evidence=[_evidence("blocked_by_gate")],
            leaf_form_fields={
                str(s1.id): [
                    {"tag": "input", "type": "email", "name_or_id": "email",
                     "nearby_label_text": "Email address"},
                ]
            },
            leaf_visible_text={str(s1.id): "Enter your credentials"},
            leaf_titles={str(s1.id): "Sign In"},
        )

        text = bundle_to_prompt_text(bundle)

        # Must contain readable sections
        assert "=== EXPLORATION SUMMARY ===" in text
        assert "=== TRANSITION TYPES ===" in text
        assert "=== FLAGS (from Evidence) ===" in text
        assert "=== LEAF STATE DETAILS ===" in text

        # Must contain concrete data
        assert "https://example.com" in text
        assert "States visited: 2" in text
        assert "click: 1" in text
        assert "had_gate: True" in text

        # Leaf details
        assert "Sign In" in text
        assert "Enter your credentials" in text
        assert "Email address" in text
        assert "email" in text

    def test_empty_bundle_no_crash(self):
        """Empty bundle must serialize without crashing."""
        bundle = build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[],
            transitions=[],
            evidence=[],
            leaf_form_fields={},
            leaf_visible_text={},
            leaf_titles={},
        )
        text = bundle_to_prompt_text(bundle)
        assert isinstance(text, str)
        assert len(text) > 0
        assert "0" in text  # num_states = 0
