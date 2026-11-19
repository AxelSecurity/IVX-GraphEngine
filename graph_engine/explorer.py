"""BFS state-graph explorer — passive redirects + click interactions.

Implements the BFS loop from ARCHITECTURE.md using Playwright async API.
Handles passive transitions (http_3xx, meta_refresh, js_location) and the
first interactive transition: click on scored actionable elements.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

from lxml import html as lxml_html
from playwright.async_api import Browser, BrowserContext, Page

from graph_engine.actions import enumerate_actionable
from graph_engine.budget import Budget
from graph_engine.classifier.form_inventory import scan_form_fields
from graph_engine.config import settings
from graph_engine.dom_hash import normalise_and_hash
from graph_engine.gate_solver import detect_captcha, try_pass_gate
from graph_engine.models import (
    AnalysisTarget,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    TransitionKind,
)

# ---------------------------------------------------------------------------
# Init script injected into every page to intercept JS-driven navigations
# ---------------------------------------------------------------------------

# Technique:
#   We override location.assign, location.replace, and window.open so that
#   JS-driven redirects are *recorded* instead of executed immediately.
#   The explorer reads the recorded URLs after the page settles and creates
#   `js_location` / `new_tab` transitions.
#
#   For the bare `window.location = url` / `window.location.href = url`
#   pattern, overriding the Location prototype setters is fragile across
#   browser versions.  Instead we install a `page.route()` interceptor on
#   the Playwright side that aborts any *navigation* request not initiated
#   by our own `page.goto()` call and records its URL — see
#   `_install_navigation_guard()`.
#
_INIT_SCRIPT = """
(() => {
    if (window.__ge_patched) return;
    window.__ge_patched = true;
    window.__ge_js_locations = [];

    const record = (url, method) => {
        if (url && typeof url === 'string' && url.length > 0) {
            window.__ge_js_locations.push({url: String(url), method});
        }
    };

    // location.assign  (commonly used by frameworks)
    const _assign = window.location.assign.bind(window.location);
    window.location.assign = function(url) {
        record(url, 'assign');
        // Do NOT call _assign — we control navigation timing.
    };

    // location.replace
    const _replace = window.location.replace.bind(window.location);
    window.location.replace = function(url) {
        record(url, 'replace');
        // Do NOT call _replace.
    };

    // window.open  →  treat as new-tab candidate later
    window.open = function(url) {
        record(url, 'open');
        return null;
    };
})();
"""

# Regex extracting the URL from <meta http-equiv="refresh" content="…">
_META_REFRESH_RE = re.compile(
    r'(?P<url>https?://[^\s"\']+|[^\s"\']*\.php[^\s"\']*)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Settle post-navigation — adaptive polling
# ---------------------------------------------------------------------------
# A delay of 2s+ before a JS redirect is a known evasion pattern against
# crawlers with a short fixed settle wait: the old fixed 1.5s wait missed
# it (found on a real TDS kit).  Same scheme as try_pass_gate() in
# gate_solver.py: periodic poll, early exit, hard ceiling.

_SETTLE_POLL_INTERVAL = 0.5    # seconds between polls
_SETTLE_MIN_OBSERVE = 1.5      # minimum observation window: the "quiet"
                               # early exit never fires before it (equals
                               # the old fixed wait → no coverage regression)
_SETTLE_QUIET_CYCLES = 2       # consecutive mature cycles with nothing
                               # new → page is stable, stop waiting

# ---------------------------------------------------------------------------
# Gate settle — fase 3 di try_pass_gate() (attesa post-click del checkbox)
# ---------------------------------------------------------------------------
# Ridotta nel fast path (captcha_wait_s <= 4) per non bruciare
# budget sul secondo rilevamento; standard altrimenti.

_GATE_SETTLE_FAST_S = 1.5
_GATE_SETTLE_DEFAULT_S = 3.0

# ---------------------------------------------------------------------------
# Attese dopo un'interazione — al posto di sleep fissi e networkidle
# ---------------------------------------------------------------------------
# networkidle non arriva MAI su pagine con analytics/polling (si pagava
# sempre il timeout pieno) e torna SUBITO se la pagina era già idle prima
# del click (una fetch lanciata dal click veniva persa).  Al suo posto:
#   - replay: lo stato di arrivo è noto → si attende che la pagina mostri
#     proprio quel dom_hash (tetto = vecchio sleep fisso: mai peggio);
#   - click esplorativo: si attende che le richieste xhr/fetch/document
#     partite DOPO il click siano finite e che il DOM resti fermo per
#     ``_QUIET_WINDOW_S`` (tetto = vecchio networkidle 3s + sleep 0.5s).
_WAIT_POLL_S = 0.1
_WAIT_MIN_S = 0.3
_QUIET_WINDOW_S = 0.5
_CLICK_WAIT_CAP_S = 3.5
_TRACKED_RESOURCE_TYPES = frozenset({"xhr", "fetch", "document"})

# MutationObserver: registra l'istante dell'ultima mutazione del DOM.
_INSTALL_MUTATION_PROBE = """() => {
    window.__ge_last_mut = performance.now();
    if (window.__ge_mo) return;
    const mo = new MutationObserver(() => { window.__ge_last_mut = performance.now(); });
    mo.observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
    window.__ge_mo = mo;
}"""
# ms dall'ultima mutazione; -1 = documento nuovo (sonda assente), -2 =
# documento non ancora completo (parsing o risorse in caricamento).
_READ_MUTATION_PROBE = """() => {
    if (document.readyState !== 'complete') return -2;
    if (!window.__ge_mo) return -1;
    return performance.now() - window.__ge_last_mut;
}"""


class _RequestTracker:
    """Conta le richieste xhr/fetch/document ancora in volo su una pagina.

    Va agganciato PRIMA dell'interazione: conta solo ciò che parte dopo.
    I document dei sub-frame (iframe di widget/CAPTCHA) sono ignorati.
    """

    def __init__(self, page: Page) -> None:
        self._page = page
        self._inflight: set = set()

    @property
    def inflight(self) -> int:
        return len(self._inflight)

    def _on_request(self, request) -> None:
        try:
            if request.resource_type not in _TRACKED_RESOURCE_TYPES:
                return
            if (
                request.resource_type == "document"
                and request.frame != self._page.main_frame
            ):
                return
        except Exception:
            return
        self._inflight.add(request)

    def _on_done(self, request) -> None:
        self._inflight.discard(request)

    def attach(self) -> "_RequestTracker":
        self._page.on("request", self._on_request)
        self._page.on("requestfinished", self._on_done)
        self._page.on("requestfailed", self._on_done)
        return self

    def detach(self) -> None:
        for event, handler in (
            ("request", self._on_request),
            ("requestfinished", self._on_done),
            ("requestfailed", self._on_done),
        ):
            try:
                self._page.remove_listener(event, handler)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Explorer
# ---------------------------------------------------------------------------


def _request_post_data_text(request) -> Optional[str]:
    """POST body di una richiesta Playwright come testo, senza crashare.

    ``request.post_data`` decodifica il body base64 come UTF-8 e lancia
    ``UnicodeDecodeError`` sui body binari (es. gzip — magic byte 0x8b):
    un POST del genere faceva esplodere il callback pyee del listener HAR
    (visto live su google.com, POST compresso).  In quel caso si registra
    il buffer codificato in base64 con prefisso ``<base64>`` invece di
    perdere l'entry o propagare l'eccezione.
    """
    try:
        return request.post_data
    except UnicodeDecodeError:
        raw = request.post_data_buffer
        if not raw:
            return None
        return "<base64>" + base64.b64encode(raw).decode("ascii")


class _PageCtx:
    """Stato della navigation guard e del replay di UNA pagina.

    Era un insieme di flag dell'istanza condivisi da tutte le pagine:
    con più pagine attive insieme (azioni in parallelo) un replay su una
    pagina avrebbe sospeso la guardia di un'altra.
    """

    __slots__ = ("replaying", "our_goto_active", "intercepted")

    def __init__(self) -> None:
        # True durante il replay: niente nuovi stati, navigazioni lasciate
        # passare (si sta solo riposizionando la pagina).
        self.replaying = False
        # True durante i nostri page.goto(): la guardia non li intercetta.
        self.our_goto_active = False
        # Navigazioni avviate dalla pagina e intercettate dalla guardia.
        self.intercepted: list[dict] = []


class StateGraphExplorer:
    """BFS explorer that builds a State → Transition graph for a single URL.

    Usage::

        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            explorer = StateGraphExplorer(browser)
            target = await explorer.run("https://example.com")
            # target.id  → root AnalysisTarget UUID
            # explorer.states, explorer.transitions, explorer.evidence
    """

    # ------------------------------------------------------------------
    def __init__(
        self,
        browser: Browser,
        profile: Optional[dict] = None,
        page_timeout_ms: int = 30000,
        ignore_https_errors: bool = True,
    ) -> None:
        self._browser = browser
        self._profile: dict = profile or {}
        self._page_timeout_ms = page_timeout_ms
        # True di default: il modulo deve VEDERE cosa c'è dietro un
        # errore di certificato (pattern classico del phishing: www su
        # sottodomini blogspot senza cert valido).  L'errore TLS non va
        # perso: la sonda L3 (redirect_chain) lo registra comunque come
        # evidenza, e il prefilter lo valuta deterministicamente.
        self._ignore_https_errors = ignore_https_errors

        self._artifact_base: Path = Path("data") / "graph_artifacts"

        # Accumulators — populated during run()
        self.target: Optional[AnalysisTarget] = None
        self.states: list[State] = []
        self.transitions: list[Transition] = []
        self.evidence: list[Evidence] = []
        # Campi form visibili per stato (str(state.id) → scan_form_fields):
        # inventario PASSIVO (sola lettura, nessun fill/click) per L5.
        self.form_fields_by_state: dict[str, list[dict]] = {}

        # Internal BFS state
        self._visited: set[str] = set()  # dom_hash set
        self._start_ts: float = 0.0
        self._node_count: int = 0

        # Stato per pagina di guardia e replay (vedi _PageCtx / _ctx).
        self._page_ctx: dict[int, _PageCtx] = {}
        # Azioni di uno stato eseguite in parallelo (vedi _run_actions).
        self._parallel_actions: int = max(1, int(settings.l4_parallel_actions))
        self._action_slots: Optional[asyncio.Semaphore] = None
        # Esito della scorciatoia URL per stato (vedi _replay_by_url):
        # True = raggiungibile con un goto diretto, False = serve il replay.
        self._reach_by_url: dict[uuid.UUID, bool] = {}

        # Artifact capture
        self._capture_artifacts_flag: bool = True
        self._network_captures: dict[int, list[dict]] = {}
        self._page_listeners: dict[int, list[tuple]] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        start_url: str,
        budget: Optional[Budget] = None,
        profile: Optional[dict] = None,
        capture_artifacts: bool = True,
        top_n_actions: int = 3,
        captcha_wait_s: int = 8,
        settle_max_wait_s: float = 4.0,
        target_id: Optional[uuid.UUID] = None,
        cloaking_profile: Optional[dict] = None,
    ) -> AnalysisTarget:
        """Explore *start_url* passively and return the populated AnalysisTarget.

        The BFS respects *budget* limits and collects every State, Transition,
        and Evidence in ``self.states``, ``self.transitions``, ``self.evidence``.

        When *capture_artifacts* is True (default), a HAR file, PNG screenshot,
        and DOM snapshot are saved to ``data/graph_artifacts/<target_id>/<state_id>/``
        for every visited state.

        *top_n_actions* limits how many scored click candidates are attempted
        per state (default 3). Set to 0 to disable click exploration entirely.

        *captcha_wait_s* is the max wait time for invisible gate auto-resolve
        (default 8).  Set to 0 to skip gate detection entirely.

        *settle_max_wait_s* is the max post-load wait for delayed JS
        redirects (default 4.0).  A delay of 2s+ before a JS redirect is a
        known evasion pattern against crawlers with a short fixed settle
        wait (the old fixed 1.5s missed it, found on a real TDS kit): the
        settle poll exits early as soon as an interception appears, and
        pages with no redirects never pay the full ceiling.

        *target_id* is the UUID to use for the ``AnalysisTarget`` created
        internally.  When ``None`` (default), a new UUID is generated — this
        preserves backward compatibility with all existing callers.  When
        provided (by the API layer), all child records (states, transitions,
        evidence) are born with this UUID from the start, eliminating the
        need for post-hoc re-parenting.

        *cloaking_profile* is the divergent profile detected by L3
        (``{"user_agent", "headers"}``).  When set, a SECOND branch is
        explored with this profile BEFORE the primary BFS loop, linked
        to the primary root by a ``TransitionKind.cloaking_probe``
        transition.  Budget is shared (residual) and the branch max depth
        is capped at ``min(2, budget.max_depth)``.  The branch runs first
        so it is guaranteed a budget window: after the primary loop it
        would never start on targets that redirect to "infinite" sites
        (e.g. Google), where the primary tree consumes the whole global
        timeout.
        """
        budget = budget or Budget()
        self._capture_artifacts_flag = capture_artifacts
        self._top_n_actions = top_n_actions
        self._captcha_wait_s = captcha_wait_s
        self._settle_max_wait_s = settle_max_wait_s
        self._gate_settle_s = (
            _GATE_SETTLE_FAST_S
            if captcha_wait_s <= 4
            else _GATE_SETTLE_DEFAULT_S
        )
        if profile is not None:
            self._profile = profile

        self._visited.clear()
        self._page_ctx.clear()
        self._reach_by_url.clear()
        self.states.clear()
        self.transitions.clear()
        self.evidence.clear()
        self._node_count = 0
        self._start_ts = time.monotonic()

        self.target = AnalysisTarget(
            id=target_id if target_id is not None else uuid.uuid4(),
            input_url=start_url,
            status=TargetStatus.running,
        )

        # --- browser context (isolated per target) -------------------------
        extra_headers = self._profile.get("headers", {})
        context = await self._browser.new_context(
            user_agent=self._profile.get(
                "user_agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            ),
            viewport={"width": 1280, "height": 720},
            locale=self._profile.get("locale", "en-US"),
            timezone_id=self._profile.get("timezone", "America/New_York"),
            extra_http_headers=extra_headers if extra_headers else None,
            ignore_https_errors=self._ignore_https_errors,
        )
        try:
            page = await context.new_page()
            page.set_default_timeout(self._page_timeout_ms)

            # --- root state ------------------------------------------------
            root_state = await self._navigate_and_create_state(
                page, start_url, depth=0
            )
            if root_state is None:
                self.target.status = TargetStatus.error
                return self.target

            self.target.root_state_id = root_state.id
            self.target.final_url = root_state.url
            self.states.append(root_state)
            self._node_count += 1

            # --- secondo ramo cloaking (profilo divergente) ----------------
            # PRIMA del BFS primario: il ramo ha così una finestra di
            # budget garantita. Dopo il primario non partirebbe mai sui
            # target che reindirizzano a siti "infiniti" (es. Google):
            # il primario consumerebbe l'intero timeout globale.
            await self._explore_cloaking_branch(
                start_url, budget, cloaking_profile, root_state
            )

            # --- BFS loop primario -----------------------------------------
            await self._bfs_loop(page, context, budget, root_state)

            self.target.status = TargetStatus.done

        finally:
            await context.close()

        return self.target

    async def _bfs_loop(
        self,
        page,
        context,
        budget: Budget,
        start_state: State,
        max_depth_limit: Optional[int] = None,
    ) -> None:
        """BFS del grafo a partire da *start_state* su *page*/*context*.

        Corpo estratto da ``run()`` per essere riusato sul secondo ramo
        cloaking: *max_depth_limit* riduce la profondità massima del
        sotto-albero (default: ``budget.max_depth``). Budget, dedup
        (``self._visited``) e conteggio nodi restano CONDIVISI tra
        albero primario e ramo divergente.
        """
        depth_limit = (
            max_depth_limit if max_depth_limit is not None else budget.max_depth
        )
        frontier: asyncio.Queue[State] = asyncio.Queue()
        await frontier.put(start_state)

        while not frontier.empty():
            if not self._within_budget(budget):
                break

            state = await frontier.get()

            if state.dom_hash in self._visited:
                continue
            self._visited.add(state.dom_hash)

            if state.depth >= depth_limit:
                continue

            try:
                # Replay the transition path so *page* shows this state's DOM
                # (critical for SPA / multi-step forms where URL doesn't change).
                if state.depth > 0:
                    replay_ok = await self._replay_to_state(page, state)
                    if not replay_ok:
                        # Replay fell back to goto(state.url) — the DOM may
                        # differ from the original exploration; treat as leaf.
                        continue

                # ---- gate detection / solving --------------------------------
                if self._captcha_wait_s > 0:
                    captcha = await detect_captcha(page)
                    if captcha is not None:
                        gate_passed = await try_pass_gate(
                            page,
                            self._captcha_wait_s,
                            settle_s=self._gate_settle_s,
                        )
                        if gate_passed:
                            # The DOM changed (gate iframe gone / replaced) —
                            # record a new State + Transition.
                            post_html = await page.content()
                            post_hash = await asyncio.to_thread(normalise_and_hash, post_html)
                            post_url = page.url

                            if post_hash != state.dom_hash:
                                gate_state = State(
                                    target_id=self.target.id,  # type: ignore[union-attr]
                                    url=post_url,
                                    dom_hash=post_hash,
                                    depth=state.depth + 1,
                                )
                                await self._scan_forms(gate_state, page)
                                if self._capture_artifacts_flag:
                                    await self._save_artifacts(
                                        gate_state, page, post_html, []
                                    )
                                gate_transition = Transition(
                                    target_id=self.target.id,  # type: ignore[union-attr]
                                    from_state=state.id,
                                    to_state=gate_state.id,
                                    kind=TransitionKind.gate_solved,
                                    trigger={
                                        "provider": captcha,
                                        "wait_s": self._captcha_wait_s,
                                    },
                                )
                                self.states.append(gate_state)
                                self.transitions.append(gate_transition)
                                self._node_count += 1
                                if gate_state.dom_hash not in self._visited:
                                    await frontier.put(gate_state)
                            continue
                        else:
                            # Gate still present — record and treat as leaf.
                            self._record_error(
                                scope=EvidenceScope.state,
                                scope_id=state.id,
                                key="blocked_by_gate",
                                message=(
                                    f"Gate not passed after "
                                    f"{self._captcha_wait_s}s: {captcha}"
                                ),
                            )
                            continue

                # Enumerate *passive* actions from this state
                actions = await self._enumerate_passive_actions(page, state)

                # Enumerate *click* actions if enabled
                if self._top_n_actions > 0:
                    click_actions = await self._enumerate_click_actions(
                        page, state
                    )
                    actions.extend(click_actions)

                for new_state in await self._run_actions(
                    page, context, state, actions, budget
                ):
                    if new_state.dom_hash not in self._visited:
                        await frontier.put(new_state)

            except Exception as exc:
                self._record_error(
                    scope=EvidenceScope.state,
                    scope_id=state.id,
                    key="unhandled_node_error",
                    message=(
                        f"Unhandled error processing state "
                        f"{state.id}: {exc}"
                    ),
                )

    async def _run_actions(
        self,
        page,
        context,
        state: State,
        actions: list,
        budget: Budget,
    ) -> list[State]:
        """Esegue le azioni di *state* IN PARALLELO e registra i risultati.

        Ogni azione lavora su una pagina propria (stato di guardia per
        pagina, vedi ``_PageCtx``); al massimo ``L4_PARALLEL_ACTIONS``
        insieme.  Ogni azione ha come tetto il tempo residuo del budget:
        il timeout globale vale anche DENTRO un'azione (prima veniva
        controllato solo tra un'azione e l'altra).

        Stati e transizioni vengono registrati nell'ORDINE DEI CANDIDATI
        e solo fino ai nodi rimasti nel budget: il grafo è lo stesso che
        produrrebbe l'esecuzione sequenziale, indipendentemente da quale
        azione finisce prima.
        """
        if not actions or not self._within_budget(budget):
            return []
        if self._action_slots is None:
            self._action_slots = asyncio.Semaphore(self._parallel_actions)
        slots = self._action_slots

        async def _one(action):
            async with slots:
                remaining = budget.timeout_s - (time.monotonic() - self._start_ts)
                if remaining <= 0:
                    return None
                try:
                    return await asyncio.wait_for(
                        self._execute_action(page, context, state, action),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    self._record_error(
                        scope=EvidenceScope.state,
                        scope_id=state.id,
                        message=(
                            f"Action interrupted by the exploration budget "
                            f"({action.get('kind') if isinstance(action, dict) else action})"
                        ),
                    )
                    return None

        results = await asyncio.gather(
            *(_one(a) for a in actions), return_exceptions=True
        )

        new_states: list[State] = []
        for result in results:
            if isinstance(result, BaseException):
                self._record_error(
                    scope=EvidenceScope.state,
                    scope_id=state.id,
                    key="unhandled_node_error",
                    message=f"Unhandled action error on state {state.id}: {result}",
                )
                continue
            if result is None:
                continue
            if self._node_count >= budget.max_nodes:
                break
            new_state, transition = result
            self.states.append(new_state)
            if transition is not None:
                self.transitions.append(transition)
            self._node_count += 1
            new_states.append(new_state)
        return new_states

    # ------------------------------------------------------------------
    # Cloaking probe branch (second L4 tree with the divergent profile)
    # ------------------------------------------------------------------

    def _record_cloaking_probe_evidence(
        self,
        status: str,
        reason: str = "",
        detail: str = "",
    ) -> None:
        """Evidenza L4 sull'esito del ramo cloaking (weight 0: telemetria)."""
        value: dict = {"status": status}
        if reason:
            value["reason"] = reason
        if detail:
            value["detail"] = detail
        self.evidence.append(
            Evidence(
                target_id=self.target.id,  # type: ignore[union-attr]
                scope=EvidenceScope.target,
                scope_id=self.target.id,  # type: ignore[union-attr]
                layer="L4",
                key="cloaking_probe",
                value=json.dumps(value),
                weight=0.0,
                produced_by="StateGraphExplorer",
            )
        )

    async def _explore_cloaking_branch(
        self,
        start_url: str,
        budget: Budget,
        cloaking_profile: Optional[dict],
        root_state: State,
    ) -> None:
        """Secondo ramo L4 col profilo divergente rilevato da L3.

        Quando L3 rileva cloaking, il contenuto servito al profilo
        divergente (es. Googlebot) non è mai visibile al visitatore
        normale: qui viene esplorato come albero parallelo collegato al
        root primario da una ``Transition(cloaking_probe)``.

        Viene eseguito subito dopo la navigazione del root primario,
        PRIMA del BFS primario: così il ramo ha una finestra di budget
        garantita (il primario, su target che reindirizzano a siti
        infiniti, consumerebbe l'intero timeout globale).

        Vincoli:
        - budget CONDIVISO (stessi ``_node_count``/``_start_ts``);
        - riserva di 2 nodi: il ramo parte solo con abbastanza budget,
          altrimenti evidenza status ``skipped``;
        - max_depth del sotto-albero ridotta a ``min(2, budget.max_depth)``;
        - dedup contro il root primario (non ancora in ``self._visited``)
          e contro gli stati già visitati;
        - contenimento errori: un fallimento produce evidenza
          ``cloaking_probe_error`` e MAI una eccezione verso l'esterno.
        """
        if cloaking_profile is None:
            return

        if (
            self._node_count >= budget.max_nodes - 2
            or not self._within_budget(budget)
        ):
            self._record_cloaking_probe_evidence(
                status="skipped",
                reason="budget",
                detail=(
                    f"residual budget insufficient: {self._node_count}/"
                    f"{budget.max_nodes} nodes used"
                ),
            )
            return

        context2 = await self._browser.new_context(
            user_agent=cloaking_profile.get(
                "user_agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            ),
            viewport={"width": 1280, "height": 720},
            locale="en-US",
            timezone_id="America/New_York",
            extra_http_headers=cloaking_profile.get("headers") or None,
            ignore_https_errors=self._ignore_https_errors,
        )
        try:
            page2 = await context2.new_page()
            page2.set_default_timeout(self._page_timeout_ms)

            div_root = await self._navigate_and_create_state(
                page2, start_url, depth=0
            )
            if div_root is None:
                self._record_cloaking_probe_evidence(
                    status="error",
                    reason="navigation",
                    detail="divergent-profile root navigation failed",
                )
                return

            if (
                div_root.dom_hash == root_state.dom_hash
                or div_root.dom_hash in self._visited
            ):
                self._record_cloaking_probe_evidence(
                    status="deduped",
                    reason="duplicate_dom",
                    detail=(
                        "divergent root dom_hash already explored: "
                        f"{div_root.dom_hash}"
                    ),
                )
                return

            self.states.append(div_root)
            self._node_count += 1

            probe_transition = Transition(
                target_id=self.target.id,  # type: ignore[union-attr]
                from_state=self.target.root_state_id,  # type: ignore[union-attr]
                to_state=div_root.id,
                kind=TransitionKind.cloaking_probe,
                trigger={
                    "user_agent": cloaking_profile.get("user_agent"),
                    "reason": "divergent_profile_detected",
                },
            )
            self.transitions.append(probe_transition)

            self._record_cloaking_probe_evidence(
                status="explored",
                reason="divergent_profile_detected",
                detail=(
                    f"exploring {start_url} as "
                    f"{cloaking_profile.get('user_agent')}"
                ),
            )

            await self._bfs_loop(
                page2,
                context2,
                budget,
                div_root,
                max_depth_limit=min(2, budget.max_depth),
            )
        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.target,
                scope_id=self.target.id,  # type: ignore[union-attr]
                key="cloaking_probe_error",
                message=str(exc),
            )
        finally:
            await context2.close()

    # ------------------------------------------------------------------
    # Budget
    # ------------------------------------------------------------------

    def _within_budget(self, budget: Budget) -> bool:
        if self._node_count >= budget.max_nodes:
            return False
        if (time.monotonic() - self._start_ts) >= budget.timeout_s:
            return False
        return True

    # ------------------------------------------------------------------
    # Stato per pagina
    # ------------------------------------------------------------------

    def _ctx(self, page: Page) -> _PageCtx:
        """Stato di guardia/replay di *page* (creato al primo uso)."""
        ctx = self._page_ctx.get(id(page))
        if ctx is None:
            ctx = _PageCtx()
            self._page_ctx[id(page)] = ctx
        return ctx

    def _release_page(self, page: Page) -> None:
        """Dimentica lo stato di una pagina chiusa (gli id vengono riusati)."""
        self._page_ctx.pop(id(page), None)

    # ------------------------------------------------------------------
    # Attese intelligenti
    # ------------------------------------------------------------------

    async def _wait_for_dom_hash(
        self, page: Page, expected_hash: Optional[str], cap_s: float,
    ) -> bool:
        """Attende che *page* mostri il DOM atteso (replay verso uno stato noto).

        Esce appena ``dom_hash`` coincide con *expected_hash* a documento
        completo (``readyState == complete``: gli script async hanno
        avuto modo di agganciare i listener) e dopo almeno
        ``_WAIT_MIN_S``.  Altrimenti attende fino a *cap_s* — il vecchio
        sleep fisso, quindi mai più di prima.  Restituisce True se il DOM
        atteso è stato visto.
        """
        started = time.monotonic()
        deadline = started + cap_s
        while True:
            now = time.monotonic()
            if now >= deadline:
                return False
            await asyncio.sleep(min(_WAIT_POLL_S * 2, deadline - now))
            if expected_hash is None or time.monotonic() - started < _WAIT_MIN_S:
                continue
            try:
                if await page.evaluate("() => document.readyState") != "complete":
                    continue
                html_str = await page.content()
            except Exception:
                continue  # navigazione in corso
            if await asyncio.to_thread(normalise_and_hash, html_str) == expected_hash:
                return True

    async def _arm_interaction_wait(self, page: Page) -> _RequestTracker:
        """Da chiamare PRIMA di un'interazione: aggancia contatore richieste
        e sonda delle mutazioni DOM."""
        tracker = _RequestTracker(page).attach()
        try:
            await page.evaluate(_INSTALL_MUTATION_PROBE)
        except Exception:
            pass
        return tracker

    async def _wait_after_interaction(
        self,
        page: Page,
        tracker: _RequestTracker,
        cap_s: float = _CLICK_WAIT_CAP_S,
    ) -> None:
        """Attende la fine degli effetti di un click di esito ignoto.

        Fine = (dopo almeno ``_WAIT_MIN_S``) nessuna richiesta
        xhr/fetch/document partita dopo il click ancora in volo, documento
        completo e DOM fermo da ``_QUIET_WINDOW_S``.  Una navigazione
        viene seguita: sul nuovo documento la sonda viene reinstallata.
        Tetto *cap_s* (= vecchio networkidle 3s + sleep 0.5s).
        """
        started = time.monotonic()
        deadline = started + cap_s
        try:
            while True:
                now = time.monotonic()
                if now >= deadline:
                    return
                await asyncio.sleep(min(_WAIT_POLL_S, deadline - now))
                try:
                    since_mut_ms = await page.evaluate(_READ_MUTATION_PROBE)
                except Exception:
                    continue  # navigazione in corso
                if since_mut_ms == -1:
                    # Documento nuovo (navigazione): sonda da reinstallare.
                    try:
                        await page.evaluate(_INSTALL_MUTATION_PROBE)
                    except Exception:
                        pass
                    continue
                if since_mut_ms < 0:
                    continue  # documento non ancora completo
                if time.monotonic() - started < _WAIT_MIN_S:
                    continue
                if tracker.inflight:
                    continue
                if since_mut_ms / 1000.0 >= _QUIET_WINDOW_S:
                    return
        finally:
            tracker.detach()

    # ------------------------------------------------------------------
    # Transition path reconstruction
    # ------------------------------------------------------------------

    def _expected_hash(self, transition: Transition) -> Optional[str]:
        """dom_hash dello stato di arrivo di *transition* (None se ignoto)."""
        target = self._find_state_by_id(transition.to_state)
        return target.dom_hash if target else None

    def _find_state_by_id(self, state_id: uuid.UUID) -> Optional[State]:
        """Look up a State by its id in ``self.states``."""
        for s in self.states:
            if s.id == state_id:
                return s
        return None

    def _build_transition_path(self, state: State) -> list[Transition]:
        """Walk backwards from *state* to root and return the ordered path.

        The returned list is empty for the root state.  For every other state
        it contains the Transitions that were traversed from root → *state*,
        in chronological order.
        """
        rev: list[Transition] = []
        current_id: uuid.UUID = state.id
        while True:
            t = next(
                (t for t in self.transitions if t.to_state == current_id), None
            )
            if t is None:
                break
            rev.append(t)
            current_id = t.from_state
        rev.reverse()
        return rev

    async def _replay_to_state(self, page: Page, state: State) -> bool:
        """Bring *page* to the same DOM as *state* by replaying the transition path.

        Returns ``True`` if the replay completed cleanly.  Returns ``False``
        when a click replay failed and we fell back to ``goto(state.url)`` —
        in that case the caller **must not** enumerate new actions from this
        state (it is a leaf).

        The ``_replaying`` flag suppresses leak of intercepted navigations
        into the exploration accumulators.
        """
        was_replaying = self._ctx(page).replaying
        self._ctx(page).replaying = True
        try:
            return await self._replay_to_state_impl(page, state)
        finally:
            self._ctx(page).replaying = was_replaying
            # Discard any navigation intercepts that fired during replay —
            # they belong to the original exploration, not new discovery.
            self._ctx(page).intercepted.clear()
            try:
                await page.evaluate(
                    "() => { window.__ge_js_locations = []; }"
                )
            except Exception:
                pass

    async def _page_shows(self, page: Page, state: State) -> bool:
        """True se *page* mostra già *state* (stesso URL e stesso dom_hash)."""
        try:
            if page.url.rstrip("/") != state.url.rstrip("/"):
                return False
            if await page.evaluate("() => document.readyState") != "complete":
                return False
            html_str = await page.content()
        except Exception:
            return False
        return await asyncio.to_thread(normalise_and_hash, html_str) == state.dom_hash

    async def _replay_by_url(
        self, page: Page, state: State, path: list[Transition],
    ) -> bool:
        """Scorciatoia: ``goto(state.url)`` verificato dal dom_hash.

        Tentata solo per stati raggiunti CAMBIANDO URL (lo stato padre ha
        un URL diverso) — un click in una SPA non è raggiungibile così.
        Il context conserva i cookie (gate già superati, sessione del
        kit), quindi spesso basta una navigazione invece del replay dalla
        radice.  L'esito è ricordato per stato: un tentativo fallito non
        si ripete.
        """
        if not path or self._reach_by_url.get(state.id) is False:
            return False
        parent = self._find_state_by_id(path[-1].from_state)
        if parent is None or parent.url.rstrip("/") == state.url.rstrip("/"):
            return False
        ctx = self._ctx(page)
        ctx.our_goto_active = True
        try:
            await page.goto(state.url, wait_until="domcontentloaded")
        except Exception:
            self._reach_by_url[state.id] = False
            return False
        finally:
            ctx.our_goto_active = False
        reached = await self._wait_for_dom_hash(page, state.dom_hash, cap_s=1.5)
        self._reach_by_url[state.id] = reached
        return reached

    def _record_replay_divergence(self, state: State) -> None:
        """Evidenza diagnostica: il replay completo non ha riprodotto il DOM."""
        self.evidence.append(
            Evidence(
                target_id=self.target.id,  # type: ignore[union-attr]
                scope=EvidenceScope.state,
                scope_id=state.id,
                layer="L4",
                key="replay_divergence",
                value=f"Replay to state {state.id} ended on a different DOM",
                weight=0.0,
                produced_by="StateGraphExplorer",
            )
        )

    async def _replay_to_state_impl(self, page: Page, state: State) -> bool:
        """Inner implementation — see ``_replay_to_state``.

        Ordine: (1) la pagina mostra già lo stato → niente da fare;
        (2) scorciatoia URL verificata; (3) replay completo dalla radice,
        con verifica finale del DOM (``replay_divergence`` se diverso).
        """
        if await self._page_shows(page, state):
            return True

        path = self._build_transition_path(state)

        if await self._replay_by_url(page, state, path):
            return True

        if not path:
            # Root — simple navigation.
            self._ctx(page).our_goto_active = True
            try:
                await page.goto(state.url, wait_until="domcontentloaded")
                await self._wait_for_dom_hash(page, state.dom_hash, cap_s=1.5)
                return True
            except Exception as exc:
                self._record_error(
                    scope=EvidenceScope.state,
                    scope_id=state.id,
                    key="replay_fallback_used",
                    message=(
                        f"Replay fallback: goto({state.url}) failed: {exc}"
                    ),
                )
                return False
            finally:
                self._ctx(page).our_goto_active = False

        # Navigate to the root state's URL first.
        root_state = self._find_state_by_id(path[0].from_state)
        root_url = root_state.url if root_state else state.url
        self._ctx(page).our_goto_active = True
        try:
            await page.goto(root_url, wait_until="domcontentloaded")
        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=state.id,
                key="replay_fallback_used",
                message=(
                    f"Replay fallback: goto({root_url}) failed: {exc}"
                ),
            )
            return False
        finally:
            self._ctx(page).our_goto_active = False
        await self._wait_for_dom_hash(
            page, root_state.dom_hash if root_state else None, cap_s=1.0,
        )

        # Replay transitions in chronological order.
        for t in path:
            if t.kind == TransitionKind.gate_solved and t.trigger:
                # Re-solve the gate with the same logic used during original
                # exploration — not a simple click.
                provider = t.trigger.get("provider", "")
                wait_s = int(t.trigger.get("wait_s", self._captcha_wait_s))

                captcha = await detect_captcha(page)
                if captcha is not None:
                    gate_passed = await try_pass_gate(
                        page,
                        wait_seconds=wait_s,
                        settle_s=self._gate_settle_s,
                    )
                    if not gate_passed:
                        self._record_error(
                            scope=EvidenceScope.state,
                            scope_id=state.id,
                            key="replay_fallback_used",
                            message=(
                                f"Replay fallback: gate_solved for "
                                f"'{provider}' failed on replay for "
                                f"state {state.id} — fell back to "
                                f"goto({state.url})"
                            ),
                        )
                        self._ctx(page).our_goto_active = True
                        try:
                            await page.goto(
                                state.url, wait_until="domcontentloaded"
                            )
                        finally:
                            self._ctx(page).our_goto_active = False
                        await asyncio.sleep(1.5)
                        return False
                # Let the page settle after gate resolution.
                await self._wait_for_dom_hash(
                    page, self._expected_hash(t), cap_s=1.0,
                )

            elif t.kind == TransitionKind.click and t.trigger:
                selector = t.trigger.get("selector", "")
                if not selector:
                    continue
                try:
                    await page.click(selector, timeout=5000)
                except Exception:
                    # Path broken — fall back to URL navigation.
                    self._record_error(
                        scope=EvidenceScope.state,
                        scope_id=state.id,
                        key="replay_fallback_used",
                        message=(
                            f"Replay fallback: click on '{selector}' failed "
                            f"for state {state.id} — fell back to "
                            f"goto({state.url})"
                        ),
                    )
                    self._ctx(page).our_goto_active = True
                    try:
                        await page.goto(
                            state.url, wait_until="domcontentloaded"
                        )
                    finally:
                        self._ctx(page).our_goto_active = False
                    await asyncio.sleep(1.5)
                    return False
                # Stato di arrivo noto: si attende il suo DOM, con lo stesso
                # tetto del vecchio networkidle 3s + sleep 0.5s.
                await self._wait_for_dom_hash(
                    page, self._expected_hash(t), cap_s=_CLICK_WAIT_CAP_S,
                )
            else:
                # URL-based transitions (http_3xx, meta_refresh,
                # js_location): the browser follows them on its own while
                # replaying — wait (bounded) for the destination DOM.
                await self._wait_for_dom_hash(
                    page, self._expected_hash(t), cap_s=_CLICK_WAIT_CAP_S,
                )

        if not await self._page_shows(page, state):
            self._record_replay_divergence(state)
        return True

    # ------------------------------------------------------------------
    # Navigation + state creation
    # ------------------------------------------------------------------

    async def _settle_navigation_poll(
        self,
        page: Page,
        settle_max_wait_s: float,
    ) -> None:
        """Adaptive post-goto settle (replaces the old fixed 1.5s wait).

        Polls ``window.__ge_js_locations`` and ``self._ctx(page).intercepted``
        every ``_SETTLE_POLL_INTERVAL`` and exits IMMEDIATELY as soon as a
        new interception appears — a redirect that fires before the ceiling
        must not wait for it (same scheme as try_pass_gate() in
        gate_solver.py: periodic poll, early exit, hard ceiling).

        Otherwise keeps polling up to *settle_max_wait_s*, with an early
        exit for quiet pages: after ``_SETTLE_MIN_OBSERVE``,
        ``_SETTLE_QUIET_CYCLES`` consecutive cycles without anything new
        mean the page has stabilised, so the full ceiling is only paid when
        it is actually needed.

        Deliberately does NOT clear the stash: ``_enumerate_passive_actions``
        consumes the intercepts downstream.
        """
        started = time.monotonic()
        deadline = started + settle_max_wait_s
        seen_count = 0
        quiet_cycles = 0
        first_poll = True

        while True:
            if first_poll:
                first_poll = False  # first check immediate: redirects fired
            else:                   # during goto are seen right away
                await asyncio.sleep(_SETTLE_POLL_INTERVAL)
            if time.monotonic() >= deadline:
                break

            try:
                js_stash: list[dict] = await page.evaluate(
                    "() => window.__ge_js_locations || []"
                )
            except Exception:
                # Page torn down mid-poll: nothing to read, keep waiting.
                js_stash = []
            current = len(js_stash) + len(self._ctx(page).intercepted)

            if current > seen_count:
                break  # new interception: the redirect fired, exit now
            seen_count = current

            # Early exit for a stable page — never before the minimum
            # observation window.  Strictly ">" so a redirect at exactly
            # _SETTLE_MIN_OBSERVE still lands inside the watch window.
            if time.monotonic() - started > _SETTLE_MIN_OBSERVE:
                quiet_cycles += 1
                if quiet_cycles >= _SETTLE_QUIET_CYCLES:
                    break  # stable: don't pay the full ceiling

    async def _navigate_and_create_state(
        self,
        page: Page,
        url: str,
        depth: int,
    ) -> Optional[State]:
        """Navigate *page* to *url* and build a State from the settled page.

        Returns ``None`` on navigation error (error logged as Evidence).
        """
        # Belt-and-suspenders: during replay we must never create new State
        # objects — the replay's job is only to position the page.
        if self._ctx(page).replaying:
            return None

        network_entries: list[dict] = []

        try:
            # --- start network capture (before navigation) -----------------
            if self._capture_artifacts_flag:
                self._start_network_capture(page)

            # Install the navigation guard *before* goto so we can tell our
            # own navigations apart from JS-initiated ones.
            await self._install_navigation_guard(page)
            await page.add_init_script(_INIT_SCRIPT)

            # Navigate — the guard marks our goto as safe.
            self._ctx(page).our_goto_active = True
            await page.goto(url, wait_until="domcontentloaded")
            self._ctx(page).our_goto_active = False

            # Settle: adaptive poll (see _settle_navigation_poll).  A fixed
            # short wait loses delayed JS redirects (2s+ evasion pattern).
            # The poll never clears the stash — _enumerate_passive_actions
            # consumes it downstream.
            await self._settle_navigation_poll(page, self._settle_max_wait_s)

        except Exception as exc:
            if self._capture_artifacts_flag:
                self._stop_network_capture(page)
            self._record_error(
                scope=EvidenceScope.target,
                scope_id=self.target.id if self.target else uuid.uuid4(),
                message=f"Navigation error for {url}: {exc}",
            )
            return None

        # --- stop network capture ------------------------------------------
        if self._capture_artifacts_flag:
            network_entries = self._stop_network_capture(page)

        # --- final URL (after any HTTP redirect) ------------------------------
        final_url = page.url

        # --- capture HTML and compute hash -----------------------------------
        html_str = await page.content()
        dom_hash = await asyncio.to_thread(normalise_and_hash, html_str)

        state = State(
            target_id=self.target.id,  # type: ignore[union-attr]
            url=final_url,
            dom_hash=dom_hash,
            depth=depth,
        )
        await self._scan_forms(state, page)

        # --- save artifacts --------------------------------------------------
        if self._capture_artifacts_flag:
            await self._save_artifacts(state, page, html_str, network_entries)

        return state

    # ------------------------------------------------------------------
    # Navigation guard (Playwright route interceptor)
    # ------------------------------------------------------------------

    async def _install_navigation_guard(self, page: Page) -> None:
        """Install a route handler that aborts JS-initiated navigations.

        Any *navigation* request that fires while ``self._ctx(page).our_goto_active``
        is ``False`` is considered page-initiated: we abort it and stash
        the URL so the BFS can create a ``js_location`` transition.
        """
        self._ctx(page).intercepted.clear()

        async def _guard(route):
            if self._ctx(page).replaying:
                # During replay, let all navigations through — we are only
                # positioning the page and already clear intercepts afterwards.
                await route.continue_()
                return
            if route.request.is_navigation_request():
                # Only TOP-level navigations count as page-initiated
                # redirects: subframe/iframe requests (CAPTCHA widgets,
                # embeds) are not the page navigating away.
                if (
                    not self._ctx(page).our_goto_active
                    and route.request.frame == page.main_frame
                ):
                    self._ctx(page).intercepted.append(
                        {"url": route.request.url, "method": "href_setter"}
                    )
                    # 204 No Content, NON abort(): il browser annulla la
                    # navigazione e resta sul documento corrente.  Con
                    # abort() Chromium sostituiva la pagina con
                    # chrome-error://chromewebdata/ — lo stato (DOM,
                    # screenshot, testo, a volte l'URL) registrava la
                    # pagina d'errore di Chrome invece del contenuto reale.
                    await route.fulfill(status=204, body="")
                    return
            await route.continue_()

        await page.route("**/*", _guard)

    # ------------------------------------------------------------------
    # Action enumeration (passive only)
    # ------------------------------------------------------------------

    async def _enumerate_passive_actions(
        self, page: Page, state: State
    ) -> list[dict]:
        """Scan *state*'s DOM for redirects that do NOT require a click."""
        actions: list[dict] = []

        html_str = await page.content()

        # --- meta-refresh -------------------------------------------------
        try:
            tree = lxml_html.fromstring(html_str)
            meta_tags = tree.xpath(
                '//meta[translate(@http-equiv, "REFSH", "refsh")="refresh"]'
            )
            for meta in meta_tags:
                content = meta.get("content", "")
                target_url = self._parse_meta_refresh(content, state.url)
                if target_url:
                    actions.append(
                        {"kind": "meta_refresh", "url": target_url, "tag": content}
                    )
        except Exception:
            pass  # malformed HTML → skip meta detection for this state

        # --- js_location (from init script + route guard) ------------------
        # Accumulated during the post-goto settle poll and left in place
        # for consumption HERE (once), then cleared so the next state
        # starts clean.  The interception data — not a re-read of the
        # page — is what drives the js_location transition.
        try:
            js_locs: list[dict] = await page.evaluate(
                "() => window.__ge_js_locations || []"
            )
        except Exception:
            js_locs = []
        js_locs += self._ctx(page).intercepted
        self._ctx(page).intercepted.clear()
        try:
            await page.evaluate("() => { window.__ge_js_locations = []; }")
        except Exception:
            pass

        seen_urls: set[str] = set()
        for loc in js_locs:
            url = loc.get("url")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            actions.append(
                {"kind": "js_location", "url": url, "trigger": loc}
            )

        return actions

    def _parse_meta_refresh(self, content: str, base_url: str) -> Optional[str]:
        """Extract the target URL from a <meta http-equiv=refresh> content attr."""
        # content format: "SECONDS; url=URL"  or  "SECONDS; URL=URL"
        match = re.search(r'url\s*=\s*["\']?([^"\'\s;]+)', content, re.IGNORECASE)
        if match:
            raw = match.group(1).strip()
            if raw.startswith("http://") or raw.startswith("https://"):
                return raw
            # Relative URL
            return urljoin(base_url, raw)
        return None

    # ------------------------------------------------------------------
    # Click-action enumeration
    # ------------------------------------------------------------------

    async def _enumerate_click_actions(
        self, page: Page, state: State
    ) -> list[dict]:
        """Score and return the top-N click candidates for *state*."""
        try:
            candidates = await enumerate_actionable(page)
        except Exception:
            return []

        actions: list[dict] = []
        for c in candidates[: self._top_n_actions]:
            actions.append({
                "kind": "click",
                "selector": c.selector,
                "text": c.text,
                "combined_score": c.combined_score,
                "bounding_box": c.bounding_box,
            })
        return actions

    # ------------------------------------------------------------------
    # Click-action execution
    # ------------------------------------------------------------------

    async def _execute_click_action(
        self,
        context: BrowserContext,
        from_state: State,
        action: dict,
    ) -> Optional[tuple[State, Transition]]:
        """Click *action*'s element and detect navigation/DOM change.

        Returns ``(new_state, transition)`` — the caller records them (in
        candidate order) — or ``None`` when nothing changed.

        Strategy (revised — replay-full-path):
        1. Open a fresh page and replay the transition path to *from_state*
           (not just ``goto(url)`` — that fails for click-reached states where
           the URL never changed).
        2. Click the target element.
        3. Wait for ``networkidle`` (catches navigations) with a short timeout.
        4. If the URL changed → new state.
        5. If not, compare before/after ``dom_hash`` — mutation without navigation
           still produces a new state.
        6. If nothing changed, discard the branch (return ``None``).
        """
        selector = action["selector"]
        new_page = await context.new_page()
        new_page.set_default_timeout(self._page_timeout_ms)

        try:
            # Replay the full transition path to reach *from_state*'s DOM.
            # This correctly handles states reached via click where the URL
            # never changed (SPA, multi-step forms).  If the replay fell
            # back (the page is NOT on from_state's DOM), clicking here
            # would attribute an unrelated page to from_state: skip.
            if not await self._replay_to_state(new_page, from_state):
                return None

            # Pre-click snapshot.
            pre_html = await new_page.content()
            pre_hash = await asyncio.to_thread(normalise_and_hash, pre_html)
            pre_url = new_page.url

            # Click.
            tracker = await self._arm_interaction_wait(new_page)
            try:
                await new_page.click(selector, timeout=5000)
            except Exception:
                # Element not found / not clickable — not an error, just skip.
                tracker.detach()
                return None

            # Effetti del click: navigazione, fetch + render, mutazioni DOM.
            await self._wait_after_interaction(new_page, tracker)

            # Post-click snapshot.
            post_url = new_page.url
            post_html = await new_page.content()
            post_hash = await asyncio.to_thread(normalise_and_hash, post_html)

            # --- no observable change → discard branch -----------------------
            if post_url.rstrip("/") == pre_url.rstrip("/") and post_hash == pre_hash:
                return None

            # --- build the new State from the current page state --------------
            # Belt-and-suspenders: during replay the flag is True and we must
            # never create State / Transition objects.
            if self._ctx(new_page).replaying:
                return None

            new_state = State(
                target_id=self.target.id,  # type: ignore[union-attr]
                url=post_url,
                dom_hash=post_hash,
                depth=from_state.depth + 1,
            )
            await self._scan_forms(new_state, new_page)

            # Capture artifacts using the current page (no re-navigation).
            if self._capture_artifacts_flag:
                await self._save_artifacts(new_state, new_page, post_html, [])

            transition = Transition(
                target_id=self.target.id,  # type: ignore[union-attr]
                from_state=from_state.id,
                to_state=new_state.id,
                kind=TransitionKind.click,
                trigger={
                    "selector": selector,
                    "text": action.get("text", ""),
                    "combined_score": action.get("combined_score", 0.0),
                },
            )
            return new_state, transition

        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=from_state.id,
                message=f"Click action error ({selector}): {exc}",
            )
            return None
        finally:
            await new_page.close()
            self._release_page(new_page)

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    async def _execute_action(
        self,
        page: Page,
        context: BrowserContext,
        from_state: State,
        action: dict,
    ) -> Optional[tuple[State, Transition]]:
        """Execute *action* on a fresh page: ``(new_state, transition)`` or None.

        Nothing is recorded here: ``_run_actions`` appends states and
        transitions in candidate order.
        """
        kind_str = action["kind"]
        if kind_str == "click":
            return await self._execute_click_action(context, from_state, action)

        # --- URL-based (passive) actions ------------------------------------
        target_url = action["url"]

        kind_map = {
            "http_3xx": TransitionKind.http_3xx,
            "meta_refresh": TransitionKind.meta_refresh,
            "js_location": TransitionKind.js_location,
        }
        transition_kind = kind_map.get(kind_str, TransitionKind.http_3xx)

        # Open a fresh page for this navigation (isolated from siblings).
        new_page = await context.new_page()
        new_page.set_default_timeout(self._page_timeout_ms)

        try:
            new_state = await self._navigate_and_create_state(
                new_page, target_url, depth=from_state.depth + 1
            )

            if new_state is None:
                return None

            transition = Transition(
                target_id=self.target.id,  # type: ignore[union-attr]
                from_state=from_state.id,
                to_state=new_state.id,
                kind=transition_kind,
                trigger=action.get("trigger", action),
            )
            return new_state, transition

        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=from_state.id,
                message=f"Action execution error ({kind_str} → {target_url}): {exc}",
            )
            return None
        finally:
            await new_page.close()
            self._release_page(new_page)

    # ------------------------------------------------------------------
    # Error recording
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Error recording
    # ------------------------------------------------------------------

    def _record_error(
        self,
        scope: EvidenceScope,
        scope_id: uuid.UUID,
        message: str,
        key: str = "navigation_error",
    ) -> None:
        self.evidence.append(
            Evidence(
                target_id=self.target.id if self.target else uuid.uuid4(),  # type: ignore[union-attr]
                scope=scope,
                scope_id=scope_id,
                layer="L4",
                key=key,
                value=message,
                weight=1.0,
                produced_by="StateGraphExplorer",
            )
        )

    # ------------------------------------------------------------------
    # Artifact capture
    # ------------------------------------------------------------------

    def _start_network_capture(self, page: Page) -> None:
        """Register request/response listeners on *page* to collect HAR entries."""
        page_id = id(page)
        entries: list[dict] = []
        self._network_captures[page_id] = entries

        async def _on_request(request):
            entries.append({
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "postData": _request_post_data_text(request),
                "startedDateTime": datetime.now(timezone.utc).isoformat(),
                "_start_ms": time.monotonic(),
            })

        async def _on_response(response):
            t = time.monotonic()
            for entry in reversed(entries):
                if entry["url"] == response.url and "response_status" not in entry:
                    entry.update({
                        "response_status": response.status,
                        "response_statusText": response.status_text,
                        "response_headers": dict(response.headers),
                        "time_ms": int((t - entry["_start_ms"]) * 1000),
                    })
                    del entry["_start_ms"]
                    break

        # Clean up stale listener records for this page id if any.
        self._page_listeners.pop(page_id, None)

        page.on("request", _on_request)
        page.on("response", _on_response)
        self._page_listeners[page_id] = [
            ("request", _on_request),
            ("response", _on_response),
        ]

    def _stop_network_capture(self, page: Page) -> list[dict]:
        """Remove page listeners and return the collected entries."""
        page_id = id(page)
        for event, handler in self._page_listeners.pop(page_id, []):
            page.remove_listener(event, handler)
        return self._network_captures.pop(page_id, [])

    def _build_har(self, page_url: str, entries: list[dict]) -> dict:
        """Build a minimal HAR 1.2-compliant dictionary from captured entries."""
        har_entries = []
        for e in entries:
            request = {
                "method": e.get("method", "GET"),
                "url": e.get("url", ""),
                "headers": [
                    {"name": k, "value": v}
                    for k, v in e.get("headers", {}).items()
                ],
                "cookies": [],
                "queryString": [],
                "headersSize": -1,
                "bodySize": -1,
            }
            if e.get("postData"):
                request["postData"] = {"text": e["postData"], "mimeType": "application/x-www-form-urlencoded"}

            response = {
                "status": e.get("response_status", 0),
                "statusText": e.get("response_statusText", ""),
                "headers": [
                    {"name": k, "value": v}
                    for k, v in e.get("response_headers", {}).items()
                ],
                "cookies": [],
                "content": {"size": -1, "mimeType": "unknown"},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            }

            har_entries.append({
                "startedDateTime": e.get("startedDateTime", ""),
                "time": e.get("time_ms", -1),
                "request": request,
                "response": response,
                "cache": {},
                "timings": {"send": -1, "wait": -1, "receive": -1},
            })

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "GraphEngine", "version": "0.1.0"},
                "pages": [{
                    "id": "page_1",
                    "title": page_url,
                    "startedDateTime": har_entries[0]["startedDateTime"] if har_entries else datetime.now(timezone.utc).isoformat(),
                }],
                "entries": har_entries,
            }
        }

    async def _take_screenshot(self, page: Page, path: Path) -> None:
        """Screenshot dell'intera pagina, con tetto all'altezza.

        Oltre ``SCREENSHOT_MAX_HEIGHT`` pixel si cattura solo la parte
        superiore (clip sulla pagina intera): Azure Vision rifiuta
        immagini oltre 16000 px per lato, e logo/marchio/form stanno in
        alto.  Il DOM salvato resta completo.
        """
        cap = int(settings.screenshot_max_height)
        clip = None
        if cap > 0:
            try:
                width, height = await page.evaluate(
                    "() => [document.documentElement.clientWidth || window.innerWidth,"
                    " Math.max(document.documentElement.scrollHeight,"
                    " document.body ? document.body.scrollHeight : 0)]"
                )
                if height > cap:
                    clip = {"x": 0, "y": 0, "width": width, "height": cap}
            except Exception:
                clip = None  # misura fallita: screenshot intero come prima
        if clip is None:
            await page.screenshot(path=str(path), full_page=True)
        else:
            await page.screenshot(path=str(path), full_page=True, clip=clip)

    async def _scan_forms(self, state: State, page: Page) -> None:
        """Inventario passivo dei campi form di *state* (mai fill/click).

        Best-effort: un errore lascia la lista vuota, non blocca il BFS.
        """
        try:
            fields = await scan_form_fields(page)
        except Exception:
            fields = []
        self.form_fields_by_state[str(state.id)] = (
            fields if isinstance(fields, list) else []
        )

    async def _save_artifacts(
        self,
        state: State,
        page: Page,
        html_str: str,
        network_entries: list[dict],
    ) -> None:
        """Save screenshot, DOM snapshot, and HAR for *state* to disk.

        Each artifact is saved independently — a single failure does not
        prevent the others from being written.
        """
        target_id = self.target.id  # type: ignore[union-attr]
        base_dir = self._artifact_base / str(target_id) / str(state.id)
        base_dir.mkdir(parents=True, exist_ok=True)

        # --- screenshot ------------------------------------------------------
        try:
            screenshot_path = base_dir / "screenshot.png"
            await self._take_screenshot(page, screenshot_path)
            state.screenshot_ref = str(screenshot_path)
        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=state.id,
                message=f"Artifact error — screenshot: {exc}",
            )

        # --- DOM snapshot ----------------------------------------------------
        try:
            dom_path = base_dir / "dom.html"
            dom_path.write_text(html_str, encoding="utf-8")
        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=state.id,
                message=f"Artifact error — dom.html: {exc}",
            )

        # --- HAR -------------------------------------------------------------
        try:
            har_path = base_dir / "snapshot.har"
            har_data = self._build_har(state.url, network_entries)
            har_path.write_text(
                json.dumps(har_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            state.har_ref = str(har_path)
        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=state.id,
                message=f"Artifact error — snapshot.har: {exc}",
            )
