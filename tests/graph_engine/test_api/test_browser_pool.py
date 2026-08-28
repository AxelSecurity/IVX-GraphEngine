"""Test di regressione per il pool del browser Chromium condiviso.

Coprono il fix "reuse pooled Chromium browser across requests":

- due analisi consecutive riusano lo STESSO oggetto browser (identità,
  non solo tipo) con UN solo launch Chromium;
- i context restano isolati: il cookie impostato in un'analisi non
  compare nella successiva (ogni run apre un context fresco);
- il browser condiviso NON viene chiuso dal runner (vive con l'app);
- crash del browser condiviso → UN solo rilancio automatico;
- rilancio fallito → degrado a browser effimero per quella analisi.
"""

from __future__ import annotations

import uuid

from graph_engine.models import AnalysisTarget, State, TargetStatus
from graph_engine.storage.repository import get_target_by_id


# ---------------------------------------------------------------------------
# Fake Playwright per il pool — il pool usa ``.start()``/``.stop()``,
# NON il context manager ``async with async_playwright()``
# ---------------------------------------------------------------------------


class _FakeContext:
    """Fake di BrowserContext: tiene traccia dei cookie impostati."""

    def __init__(self):
        self.cookies = []

    async def add_cookies(self, cookies):
        self.cookies.extend(cookies)


class _PoolBrowser:
    """Fake di Browser: traccia connessione (per il crash), close e i
    context creati (per l'isolamento cookie)."""

    def __init__(self):
        self.connected = True
        self.closed = False
        self.contexts = []

    def is_connected(self) -> bool:
        return self.connected

    async def close(self) -> None:
        self.closed = True
        self.connected = False

    async def new_context(self):
        ctx = _FakeContext()
        self.contexts.append(ctx)
        return ctx


class _FakePoolChromium:
    launch_count = 0
    fail_next_launch = False

    @staticmethod
    async def launch(headless: bool = True) -> _PoolBrowser:
        _FakePoolChromium.launch_count += 1
        if _FakePoolChromium.fail_next_launch:
            _FakePoolChromium.fail_next_launch = False
            raise RuntimeError("Chromium non avviabile")
        return _PoolBrowser()


class _FakePoolPlaywright:
    """Sostituisce ``async_playwright().start()`` usato dal pool."""

    chromium = _FakePoolChromium()

    def __init__(self):
        self.stopped = False

    async def start(self):
        return self

    async def stop(self):
        self.stopped = True


def _reset_pool_fakes():
    _FakePoolChromium.launch_count = 0
    _FakePoolChromium.fail_next_launch = False


# ---------------------------------------------------------------------------
# Fake explorer — apre un context dal browser ricevuto e imposta un cookie
# per analisi, come l'explorer reale (new_context con profilo per run)
# ---------------------------------------------------------------------------


class _CookieIsolationExplorer:
    """Fake StateGraphExplorer: registra il browser ricevuto e apre un
    context fresco per run con un cookie identificativo dell'URL."""

    browsers_seen: list = []

    def __init__(self, browser, **kwargs):
        self.browser = browser
        type(self).browsers_seen.append(browser)

    async def run(self, start_url, **kwargs):
        ctx = await self.browser.new_context()
        await ctx.add_cookies(
            [{"name": "analysis_session", "value": start_url, "url": start_url}]
        )
        tid = kwargs.get("target_id") or uuid.uuid4()
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


# ---------------------------------------------------------------------------
# Test del pool standalone
# ---------------------------------------------------------------------------


class TestBrowserPool:
    """Contratti di base del BrowserPool."""

    async def test_start_acquire_returns_same_browser(self, monkeypatch):
        """``acquire()`` ripetute restituiscono lo stesso oggetto browser
        (un solo launch) e ``stop()`` chiude browser e driver."""
        from graph_engine.api.browser_pool import BrowserPool

        _reset_pool_fakes()
        pw = _FakePoolPlaywright()
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright", lambda: pw,
        )

        pool = BrowserPool()
        await pool.start()

        first = await pool.acquire()
        assert first is not None
        # La seconda acquisizione NON rilancia: stesso oggetto, un solo launch
        second = await pool.acquire()
        assert second is first
        assert _FakePoolChromium.launch_count == 1

        await pool.stop()
        assert first.closed is True
        assert pw.stopped is True

    async def test_acquire_relaunches_once_after_crash(self, monkeypatch):
        """Browser morto → UN rilancio; le acquisizioni successive riusano
        il browser rilanciato senza ulteriori launch."""
        from graph_engine.api.browser_pool import BrowserPool

        _reset_pool_fakes()
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright",
            _FakePoolPlaywright,
        )

        pool = BrowserPool()
        await pool.start()
        first = await pool.acquire()
        first.connected = False  # il processo Chromium è morto

        second = await pool.acquire()
        assert second is not None
        assert second is not first
        assert _FakePoolChromium.launch_count == 2

        third = await pool.acquire()
        assert third is second
        assert _FakePoolChromium.launch_count == 2

        await pool.stop()

    async def test_acquire_returns_none_when_relaunch_fails(self, monkeypatch):
        """Rilancio fallito → ``None`` (degrado, non eccezione); alla
        prossima acquisizione il pool riprova e riesce."""
        from graph_engine.api.browser_pool import BrowserPool

        _reset_pool_fakes()
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright",
            _FakePoolPlaywright,
        )

        pool = BrowserPool()
        await pool.start()
        first = await pool.acquire()
        first.connected = False  # crash
        _FakePoolChromium.fail_next_launch = True  # e il rilancio fallisce

        assert await pool.acquire() is None

        retry = await pool.acquire()
        assert retry is not None
        assert _FakePoolChromium.launch_count == 3

        await pool.stop()


# ---------------------------------------------------------------------------
# Integrazione pool ↔ run_full_analysis
# ---------------------------------------------------------------------------


class TestPipelineRunnerBrowserPool:
    """Il runner usa il browser condiviso del pool con context freschi."""

    async def test_two_analyses_reuse_same_browser_with_isolated_contexts(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Due analisi consecutive: stesso browser (identità), UN solo
        launch, context separati (il cookie della prima non è nella
        seconda) e browser condiviso NON chiuso dal runner."""
        from graph_engine.api.browser_pool import BrowserPool
        from graph_engine.api.pipeline_runner import run_full_analysis

        _reset_pool_fakes()
        _CookieIsolationExplorer.browsers_seen = []
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright",
            _FakePoolPlaywright,
        )
        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            _CookieIsolationExplorer,
        )

        pool = BrowserPool()
        await pool.start()

        db = str(tmp_path / "test.db")
        await run_full_analysis(
            "https://a.example.com/login", db_path=db, classify=False,
            browser_pool=pool,
        )
        await run_full_analysis(
            "https://b.example.com/login", db_path=db, classify=False,
            browser_pool=pool,
        )

        # Stessa identità browser per entrambe le analisi
        assert len(_CookieIsolationExplorer.browsers_seen) == 2
        shared = _CookieIsolationExplorer.browsers_seen[0]
        assert _CookieIsolationExplorer.browsers_seen[1] is shared

        # UN solo launch Chromium; il runner NON chiude il browser condiviso
        assert _FakePoolChromium.launch_count == 1
        assert shared.closed is False

        # Context isolati: il cookie della prima analisi non è nella seconda
        assert len(shared.contexts) == 2
        assert shared.contexts[0] is not shared.contexts[1]
        assert [c["value"] for c in shared.contexts[0].cookies] == [
            "https://a.example.com/login"
        ]
        assert [c["value"] for c in shared.contexts[1].cookies] == [
            "https://b.example.com/login"
        ]

        await pool.stop()
        assert shared.closed is True

    async def test_pool_relaunches_shared_browser_once_when_it_died(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Browser condiviso morto → UN rilancio automatico prima
        dell'analisi; l'analisi successiva riusa il browser rilanciato."""
        from graph_engine.api.browser_pool import BrowserPool
        from graph_engine.api.pipeline_runner import run_full_analysis

        _reset_pool_fakes()
        _CookieIsolationExplorer.browsers_seen = []
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright",
            _FakePoolPlaywright,
        )
        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            _CookieIsolationExplorer,
        )

        pool = BrowserPool()
        await pool.start()
        dead = await pool.acquire()
        dead.connected = False  # crash del processo Chromium condiviso

        db = str(tmp_path / "test.db")
        await run_full_analysis(
            "https://crash.example.com", db_path=db, classify=False,
            browser_pool=pool,
        )

        # UN solo rilancio; l'esploratore ha ricevuto il browser NUOVO
        assert _FakePoolChromium.launch_count == 2
        assert len(_CookieIsolationExplorer.browsers_seen) == 1
        assert _CookieIsolationExplorer.browsers_seen[0] is not dead

        # Nessun ulteriore launch alla seconda analisi
        await run_full_analysis(
            "https://crash2.example.com", db_path=db, classify=False,
            browser_pool=pool,
        )
        assert _FakePoolChromium.launch_count == 2
        assert _CookieIsolationExplorer.browsers_seen[1] is (
            _CookieIsolationExplorer.browsers_seen[0]
        )

        await pool.stop()

    async def test_pipeline_falls_back_to_ephemeral_when_relaunch_fails(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Rilancio fallito → l'analisi degrada al browser effimero
        (FakeExplorer + FakePlaywright di fake_pipeline) e completa."""
        from graph_engine.api.browser_pool import BrowserPool
        from graph_engine.api.pipeline_runner import run_full_analysis

        _reset_pool_fakes()
        monkeypatch.setattr(
            "graph_engine.api.browser_pool.async_playwright",
            _FakePoolPlaywright,
        )

        pool = BrowserPool()
        await pool.start()
        dead = await pool.acquire()
        dead.connected = False  # crash
        _FakePoolChromium.fail_next_launch = True  # anche il rilancio fallisce

        db = str(tmp_path / "test.db")
        target_id = await run_full_analysis(
            "https://degrade.example.com", db_path=db, classify=False,
            browser_pool=pool,
        )

        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.done
        # start + tentativo di rilancio fallito = 2 launch del pool
        assert _FakePoolChromium.launch_count == 2

        await pool.stop()
