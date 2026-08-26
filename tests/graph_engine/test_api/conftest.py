"""Fixture condivise per i test API.

Tutti i test usano ``httpx.AsyncClient`` + ``ASGITransport`` (nessun server
reale) e una pipeline completamente mockata (nessun browser Playwright,
nessuna rete).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.api.app import create_app
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
# Fake Playwright — sostituisce l'intero async_playwright()
# ---------------------------------------------------------------------------


class _FakeBrowser:
    """Sostituisce ``browser.close()``."""

    async def close(self) -> None:
        pass


class _FakeChromium:
    """Sostituisce ``pw.chromium.launch()``."""

    @staticmethod
    async def launch(headless: bool = True) -> _FakeBrowser:
        return _FakeBrowser()


class FakePlaywright:
    """Sostituisce ``async with async_playwright() as pw:``."""

    chromium = _FakeChromium()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


# ---------------------------------------------------------------------------
# Fake Explorer — sostituisce StateGraphExplorer (niente browser reale)
# ---------------------------------------------------------------------------


class FakeExplorer:
    """Sostituisce ``StateGraphExplorer``: ``run()`` popola target e stati
    senza aprire un browser.  Accetta ``target_id`` come l'esploratore reale."""

    def __init__(self, browser):
        self.browser = browser
        self.states: list[State] = []
        self.transitions: list[Transition] = []
        self.evidence: list[Evidence] = []
        self.target: AnalysisTarget | None = None

    async def run(
        self,
        start_url: str,
        budget=None,
        capture_artifacts: bool = True,
        top_n_actions: int = 3,
        captcha_wait_s: int = 8,
        settle_max_wait_s: float = 4.0,
        profile=None,
        target_id=None,
        cloaking_profile=None,
    ) -> AnalysisTarget:
        import uuid as _uuid

        tid = target_id if target_id is not None else _uuid.uuid4()
        self.target = AnalysisTarget(
            id=tid,
            input_url=start_url,
            final_url=start_url,
            status=TargetStatus.done,
        )
        root = State(
            target_id=self.target.id,
            url=start_url,
            dom_hash="h0",
            depth=0,
        )
        self.target.root_state_id = root.id
        self.states = [root]
        self.transitions = []
        self.evidence = []
        return self.target


class PartialExplodingExplorer(FakeExplorer):
    """Esploratore che popola 3 stati e POI esplode durante L5.

    Simula il caso reale in cui L4 produce stati con successo ma qualcosa
    a valle (es. classificazione L5) fallisce.  I 3 stati DEVONO
    sopravvivere nel DB nonostante lo status finale sia ``error``.
    """

    async def run(self, *args, **kwargs) -> AnalysisTarget:
        # Popola il target e 3 stati normalmente
        target = await super().run(*args, **kwargs)
        s2 = State(
            target_id=target.id,
            url=f"{kwargs.get('start_url', args[0] if args else '/page2')}",
            dom_hash="h1",
            depth=1,
        )
        s3 = State(
            target_id=target.id,
            url=f"{kwargs.get('start_url', args[0] if args else '/page3')}",
            dom_hash="h2",
            depth=2,
        )
        self.states.extend([s2, s3])
        return target


class ExplodingAfterExplorer(PartialExplodingExplorer):
    """Esploratore che popola stati e POI esplode — simula un fallimento
    a valle di L4 (es. L5 che lancia un'eccezione)."""

    async def run(self, *args, **kwargs) -> AnalysisTarget:
        target = await super().run(*args, **kwargs)
        raise RuntimeError("Boom! L5 classification exploded")



# ---------------------------------------------------------------------------
# Fake L5 classification
# ---------------------------------------------------------------------------


async def _fake_classification(
    target, states, transitions, evidence,
    lexical_risk_score=None, passive_risk_score=None,
) -> Verdict:
    """Classificazione finta — restituisce sempre suspicious con conf 0.5."""
    return Verdict(
        target_id=target.id,
        classification=Classification.suspicious,
        confidence=0.5,
        produced_by="foundry",
        brand=None,
        kit_family=None,
        rationale="Fake classification for testing",
    )


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path):
    """App FastAPI con db e artifact_root isolati in tmp_path."""
    return create_app(
        db_path=str(tmp_path / "test.db"),
        artifact_root=tmp_path / "artifacts",
    )


@pytest.fixture
async def client(app):
    """Client httpx con ASGITransport — nessun server reale."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Pipeline mock — sostituisce TUTTI gli stage che fanno rete/browser
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_pipeline(monkeypatch):
    """Monkeypatcha l'intera pipeline L1→L5:
    - Playwright → FakePlaywright
    - StateGraphExplorer → FakeExplorer
    - L1/L2/L3 analyzer → restituiscono evidence vuote
    - L5 classification → _fake_classification

    ``ingest()`` (L0) NON viene mockato — è puro e offline
    (refang/unwrap/canonicalize), quindi l'hash è quello reale.
    """
    monkeypatch.setattr(
        "graph_engine.api.pipeline_runner.async_playwright",
        FakePlaywright,
    )
    monkeypatch.setattr(
        "graph_engine.explorer.StateGraphExplorer",
        FakeExplorer,
    )
    # L1 è sync — la pipeline NON la awaita
    monkeypatch.setattr(
        "graph_engine.lexical.analyzer.analyze",
        lambda url, payloads: {"evidence": [], "lexical_risk_score": 0.0},
    )
    # L2 e L3 sono async — la pipeline le awaita, quindi devono
    # restituire una coroutine, non un dict direttamente

    async def _fake_l2(url, timeout_s=None):
        return {"evidence": [], "passive_risk_score": 0.0}

    async def _fake_l3(url, timeout_s=None):
        return {"evidence": [], "recommended_profile": {}}

    monkeypatch.setattr(
        "graph_engine.osint.analyzer.analyze",
        _fake_l2,
    )
    monkeypatch.setattr(
        "graph_engine.active.analyzer.analyze",
        _fake_l3,
    )
    monkeypatch.setattr(
        "graph_engine.api.pipeline_runner._run_classification",
        _fake_classification,
    )
