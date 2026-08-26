"""Tests for evidence_bundle — build + serialize, must stay compact."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, patch

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

    async def test_basic_structure(self):
        s0 = _state("aaa", 0)
        s1 = _state("bbb", 1)
        transitions = [_transition(s0.id, s1.id, TransitionKind.http_3xx)]
        evidence = [_evidence("blocked_by_gate", "cloudflare_turnstile")]

        bundle = await build_evidence_bundle(
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

    async def test_no_dom_raw_content_leaked(self):
        """Bundle must NOT contain any raw HTML/script tags accidentally."""
        s0 = _state("aaa", 0)
        # Add a leaf with visible text that looks like HTML
        leaf_text = "<script>alert(1)</script><p>Visible only</p>"

        bundle = await build_evidence_bundle(
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

    async def test_risk_scores_included_when_provided(self):
        """lexical/passive_risk_score arrivano nel bundle (servono al
        prefilter); senza input → None, non 0 ("non calcolato" ≠
        "rischio zero")."""
        s0 = _state("aaa", 0)
        kwargs = dict(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0],
            transitions=[],
            evidence=[],
            leaf_form_fields={},
            leaf_visible_text={},
            leaf_titles={},
        )

        with_scores = await build_evidence_bundle(
            **kwargs, lexical_risk_score=0.4, passive_risk_score=0.72
        )
        assert with_scores["lexical_risk_score"] == 0.4
        assert with_scores["passive_risk_score"] == 0.72

        without_scores = await build_evidence_bundle(**kwargs)
        assert without_scores["lexical_risk_score"] is None
        assert without_scores["passive_risk_score"] is None

    async def test_strong_evidence_details_extracted_with_parsed_values(self):
        """Le chiavi forti (L1/L2/L3) finiscono in strong_evidence_details
        col value JSON deserializzato — il prefilter può valutare regole
        dipendenti dal valore (typosquat distance == 1)."""
        s0 = _state("aaa", 0)
        evidence = [
            _evidence(
                "typosquat",
                '{"domain": "rnnovospid.cc", "brand": "Aruba", "distance": 1}',
            ),
            _evidence(
                "reputation_hit",
                '{"provider": "urlhaus", "listed": true}',
            ),
            _evidence("cloaking_detected", "true"),
            _evidence("navigation_error", "timeout"),  # non forte → esclusa
        ]

        bundle = await build_evidence_bundle(
            target_url="https://example.com",
            canonical_url=None,
            states=[s0],
            transitions=[],
            evidence=evidence,
            leaf_form_fields={},
            leaf_visible_text={},
            leaf_titles={},
        )

        details = bundle["strong_evidence_details"]
        assert details["typosquat"] == [
            {"domain": "rnnovospid.cc", "brand": "Aruba", "distance": 1}
        ]
        assert details["reputation_hit"] == [
            {"provider": "urlhaus", "listed": True}
        ]
        assert "cloaking_detected" in details
        assert "navigation_error" not in details

    async def test_flags_false_when_no_evidence(self):
        """All flags must be False when no Evidence entries exist."""
        s0 = _state("aaa", 0)

        bundle = await build_evidence_bundle(
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

    async def test_multiple_evidence_keys(self):
        s0 = _state("aaa", 0)
        evidence = [
            _evidence("blocked_by_gate", "cloudflare"),
            _evidence("navigation_error", "timeout"),
            _evidence("replay_fallback_used", "goto failed"),
        ]

        bundle = await build_evidence_bundle(
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

    async def test_output_is_text_not_json(self):
        """Output is human-readable labeled sections, not raw JSON."""
        s0 = _state("aaa", 0, "https://example.com")
        s1 = _state("bbb", 1, "https://example.com/step2")

        bundle = await build_evidence_bundle(
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

    async def test_empty_bundle_no_crash(self):
        """Empty bundle must serialize without crashing."""
        bundle = await build_evidence_bundle(
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


class TestVisionEnrichment:
    """Arricchimento Azure AI Vision: ``ocr_text`` e ``brands`` come campi
    SEPARATI nella entry del leaf — MAI fusi con ``visible_text``."""

    def _leaf_state_with_screenshot(self) -> State:
        """State foglia con ``screenshot_ref`` (il file NON deve esistere:
        ``analyze_screenshot`` è mockata)."""
        return State(
            target_id=uuid.uuid4(),
            url="https://example.com/canvas-login",
            dom_hash="vision",
            depth=0,
            screenshot_ref="/nonexistent/screenshot.png",
        )

    async def test_ocr_text_and_brands_are_separate_fields(self):
        """Con screenshot_ref, il risultato di analyze_screenshot popola
        ocr_text/brands come campi distinti; visible_text resta quello
        estratto dal DOM."""
        s0 = self._leaf_state_with_screenshot()

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new_callable=AsyncMock,
        ) as mock_vision:
            mock_vision.return_value = {
                "ocr_text": "Accedi al tuo account Microsoft",
                "brands": [{"name": "Microsoft", "confidence": 0.88}],
            }
            bundle = await build_evidence_bundle(
                target_url="https://example.com",
                canonical_url=None,
                states=[s0],
                transitions=[],
                evidence=[],
                leaf_form_fields={},
                # DOM senza testo: solo lo screenshot porta contenuto
                leaf_visible_text={str(s0.id): ""},
                leaf_titles={str(s0.id): ""},
            )

        leaf = bundle["leaf_states"][0]
        # Campi separati, mai fusi
        assert leaf["visible_text"] == ""
        assert leaf["ocr_text"] == "Accedi al tuo account Microsoft"
        assert leaf["brands"] == [{"name": "Microsoft", "confidence": 0.88}]
        assert "Accedi al tuo account" not in leaf["visible_text"]

        # analyze_screenshot chiamata col ref dello stato foglia
        mock_vision.assert_awaited_once_with(s0.screenshot_ref)

    async def test_leaf_without_screenshot_ref_has_empty_fields(self):
        """Senza screenshot_ref i campi restano presenti ma VUOTI —
        nessuna chiamata a analyze_screenshot (zero rete)."""
        s0 = _state("aaa", 0)

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new_callable=AsyncMock,
        ) as mock_vision:
            bundle = await build_evidence_bundle(
                target_url="https://example.com",
                canonical_url=None,
                states=[s0],
                transitions=[],
                evidence=[],
                leaf_form_fields={},
                leaf_visible_text={},
                leaf_titles={},
            )

        leaf = bundle["leaf_states"][0]
        assert leaf["ocr_text"] == ""
        assert leaf["brands"] == []
        mock_vision.assert_not_awaited()

    async def test_analyze_screenshots_false_skips_vision(self):
        """``analyze_screenshots=False`` disabilita l'arricchimento anche
        quando lo stato ha uno screenshot_ref."""
        s0 = self._leaf_state_with_screenshot()

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new_callable=AsyncMock,
        ) as mock_vision:
            bundle = await build_evidence_bundle(
                target_url="https://example.com",
                canonical_url=None,
                states=[s0],
                transitions=[],
                evidence=[],
                leaf_form_fields={},
                leaf_visible_text={},
                leaf_titles={},
                analyze_screenshots=False,
            )

        leaf = bundle["leaf_states"][0]
        assert leaf["ocr_text"] == ""
        assert leaf["brands"] == []
        mock_vision.assert_not_awaited()

    async def test_prompt_distinguishes_visual_sources(self):
        """Il testo del prompt etichetta SEPARATAMENTE le tre fonti:
        testo DOM, OCR dello screenshot e brand dello screenshot."""
        s0 = self._leaf_state_with_screenshot()

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new_callable=AsyncMock,
        ) as mock_vision:
            mock_vision.return_value = {
                "ocr_text": "Testo OCR",
                "brands": [{"name": "Aruba", "confidence": 0.9}],
            }
            bundle = await build_evidence_bundle(
                target_url="https://example.com",
                canonical_url=None,
                states=[s0],
                transitions=[],
                evidence=[],
                leaf_form_fields={},
                leaf_visible_text={str(s0.id): "Testo DOM"},
                leaf_titles={str(s0.id): "Login"},
            )

        text = bundle_to_prompt_text(bundle)
        assert "Testo visibile nel DOM" in text
        assert "Testo rilevato via OCR nello screenshot:" in text
        assert "Brand rilevati nello screenshot:" in text
        assert "Testo DOM" in text
        assert "Testo OCR" in text
        assert "Aruba (confidence 0.90)" in text
        # Le fonti restano in sezioni distinte del prompt
        assert text.index("Testo visibile nel DOM") < text.index(
            "Testo rilevato via OCR nello screenshot:"
        )

    async def test_vision_calls_run_concurrently_across_leaves(self):
        """Con più foglie con screenshot, ``analyze_screenshot`` gira in
        PARALLELO (max_active >= 2): in sequenza N foglie costerebbero
        N× il tempo di una singola chiamata Vision."""
        s0 = self._leaf_state_with_screenshot()
        s1 = State(
            target_id=s0.target_id,
            url="https://example.com/second-canvas",
            dom_hash="vision-2",
            depth=0,
            screenshot_ref="/nonexistent/screenshot-2.png",
        )

        active = 0
        max_active = 0
        release = asyncio.Event()
        started = asyncio.Event()

        async def _tracked_vision(screenshot_ref):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            started.set()
            # Blocca finché il test non rilascia: se le chiamate fossero
            # sequenziali, la seconda non partirebbe MAI e il gather
            # resterebbe appeso → il test fallirebbe in timeout.
            await asyncio.wait_for(release.wait(), timeout=2.0)
            active -= 1
            return {"ocr_text": f"OCR di {screenshot_ref}", "brands": []}

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new=_tracked_vision,
        ):
            bundle_task = asyncio.create_task(
                build_evidence_bundle(
                    target_url="https://example.com",
                    canonical_url=None,
                    states=[s0, s1],
                    transitions=[],
                    evidence=[],
                    leaf_form_fields={},
                    leaf_visible_text={},
                    leaf_titles={},
                )
            )

            # Aspetta la PRIMA chiamata, poi lascia il tempo alla seconda
            # di accumularsi in parallelo prima di rilasciare.
            await asyncio.wait_for(started.wait(), timeout=2.0)
            await asyncio.sleep(0.1)
            release.set()

            bundle = await asyncio.wait_for(bundle_task, timeout=2.0)

        assert max_active >= 2, (
            f"Vision chiamate in sequenza (max_active={max_active}) — "
            "il gather parallelo sui leaf non è attivo"
        )

        leaves = bundle["leaf_states"]
        assert leaves[0]["ocr_text"] == "OCR di /nonexistent/screenshot.png"
        assert leaves[1]["ocr_text"] == "OCR di /nonexistent/screenshot-2.png"

    async def test_vision_failure_keeps_empty_fields_for_that_leaf(self):
        """Una foglia con Vision che esplode → campi vuoti per quella
        foglia, le altre restano popolate (contenimento errori, coerente
        col comportamento sequenziale pre-refactor)."""
        s0 = self._leaf_state_with_screenshot()
        s1 = State(
            target_id=s0.target_id,
            url="https://example.com/second-canvas",
            dom_hash="vision-2",
            depth=0,
            screenshot_ref="/nonexistent/screenshot-2.png",
        )

        async def _flaky_vision(screenshot_ref):
            if "screenshot-2" in screenshot_ref:
                raise RuntimeError("Vision exploded")
            return {"ocr_text": "OCR ok", "brands": []}

        with patch(
            "graph_engine.classifier.evidence_bundle.analyze_screenshot",
            new=_flaky_vision,
        ):
            bundle = await build_evidence_bundle(
                target_url="https://example.com",
                canonical_url=None,
                states=[s0, s1],
                transitions=[],
                evidence=[],
                leaf_form_fields={},
                leaf_visible_text={},
                leaf_titles={},
            )

        leaves = bundle["leaf_states"]
        assert leaves[0]["ocr_text"] == "OCR ok"
        assert leaves[1]["ocr_text"] == ""
        assert leaves[1]["brands"] == []


class TestCloakingProbeInBundle:
    """Il ramo divergente entra nel bundle senza modifiche: leaf detection
    e transition_kinds_seen lo includono automaticamente."""

    async def test_divergent_leaf_included_and_kind_counted(self):
        s_root = _state("root", 0)
        s_div = _state("div-root", 0, url="https://example.com/?bot=1")
        s_leaf = _state("leaf", 1)
        s_div_leaf = _state("div-leaf", 1, url="https://example.com/pay")

        transitions = [
            _transition(s_root.id, s_div.id, TransitionKind.cloaking_probe),
            _transition(s_root.id, s_leaf.id, TransitionKind.click),
            _transition(s_div.id, s_div_leaf.id, TransitionKind.http_3xx),
        ]

        bundle = await build_evidence_bundle(
            target_url="https://example.com",
            canonical_url="https://example.com",
            states=[s_root, s_div, s_leaf, s_div_leaf],
            transitions=transitions,
            evidence=[],
            leaf_form_fields={},
            leaf_visible_text={
                str(s_div_leaf.id): "Pagina di pagamento",
            },
            leaf_titles={},
        )

        # cloaking_probe conteggiato tra i tipi di transizione
        assert bundle["transition_kinds_seen"]["cloaking_probe"] == 1

        # Leaf = stato senza outbound: sia il leaf primario che quello
        # del ramo divergente finiscono nel bundle
        leaf_urls = {leaf["url"] for leaf in bundle["leaf_states"]}
        assert leaf_urls == {
            "https://example.com/page?d=1",
            "https://example.com/pay",
        }
        div_leaf = next(
            leaf for leaf in bundle["leaf_states"]
            if leaf["url"] == "https://example.com/pay"
        )
        assert div_leaf["visible_text"] == "Pagina di pagamento"
