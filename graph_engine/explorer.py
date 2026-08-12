"""BFS state-graph explorer — passive redirects + click interactions.

Implements the BFS loop from ARCHITECTURE.md using Playwright async API.
Handles passive transitions (http_3xx, meta_refresh, js_location) and the
first interactive transition: click on scored actionable elements.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from lxml import html as lxml_html
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from graph_engine.actions import enumerate_actionable
from graph_engine.budget import Budget
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
# Explorer
# ---------------------------------------------------------------------------


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
    ) -> None:
        self._browser = browser
        self._profile: dict = profile or {}
        self._page_timeout_ms = page_timeout_ms

        self._artifact_base: Path = Path("data") / "graph_artifacts"

        # Accumulators — populated during run()
        self.target: Optional[AnalysisTarget] = None
        self.states: list[State] = []
        self.transitions: list[Transition] = []
        self.evidence: list[Evidence] = []

        # Internal BFS state
        self._visited: set[str] = set()  # dom_hash set
        self._start_ts: float = 0.0
        self._node_count: int = 0

        # Navigation guard state (see _install_navigation_guard)
        self._our_goto_active: bool = False
        self._intercepted_urls: list[dict] = []

        # Artifact capture
        self._capture_artifacts_flag: bool = True
        self._network_captures: dict[int, list[dict]] = {}
        self._page_listeners: dict[int, list[tuple]] = {}

        # Replay guard — when True, suppress side-effects (no new states,
        # transitions, or intercepted-urls leakage during path replay).
        self._replaying: bool = False

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
        """
        budget = budget or Budget()
        self._capture_artifacts_flag = capture_artifacts
        self._top_n_actions = top_n_actions
        self._captcha_wait_s = captcha_wait_s
        if profile is not None:
            self._profile = profile

        self._visited.clear()
        self.states.clear()
        self.transitions.clear()
        self.evidence.clear()
        self._node_count = 0
        self._start_ts = time.monotonic()

        self.target = AnalysisTarget(
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

            # --- BFS loop --------------------------------------------------
            frontier: asyncio.Queue[State] = asyncio.Queue()
            await frontier.put(root_state)

            while not frontier.empty():
                if not self._within_budget(budget):
                    break

                state = await frontier.get()

                if state.dom_hash in self._visited:
                    continue
                self._visited.add(state.dom_hash)

                if state.depth >= budget.max_depth:
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
                                page, self._captcha_wait_s
                            )
                            if gate_passed:
                                # The DOM changed (gate iframe gone / replaced) —
                                # record a new State + Transition.
                                post_html = await page.content()
                                post_hash = normalise_and_hash(post_html)
                                post_url = page.url

                                if post_hash != state.dom_hash:
                                    gate_state = State(
                                        target_id=self.target.id,  # type: ignore[union-attr]
                                        url=post_url,
                                        dom_hash=post_hash,
                                        depth=state.depth + 1,
                                    )
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

                    for action in actions:
                        if not self._within_budget(budget):
                            break
                        new_state = await self._execute_action(
                            page, context, state, action
                        )
                        if new_state is not None:
                            self.states.append(new_state)
                            self._node_count += 1
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

            self.target.status = TargetStatus.done

        finally:
            await context.close()

        return self.target

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
    # Transition path reconstruction
    # ------------------------------------------------------------------

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
        was_replaying = self._replaying
        self._replaying = True
        try:
            return await self._replay_to_state_impl(page, state)
        finally:
            self._replaying = was_replaying
            # Discard any navigation intercepts that fired during replay —
            # they belong to the original exploration, not new discovery.
            self._intercepted_urls.clear()
            try:
                await page.evaluate(
                    "() => { window.__ge_js_locations = []; }"
                )
            except Exception:
                pass

    async def _replay_to_state_impl(self, page: Page, state: State) -> bool:
        """Inner implementation — see ``_replay_to_state``."""
        path = self._build_transition_path(state)

        if not path:
            # Root — simple navigation.
            self._our_goto_active = True
            try:
                await page.goto(state.url, wait_until="domcontentloaded")
                await asyncio.sleep(1.5)
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
                self._our_goto_active = False

        # Navigate to the root state's URL first.
        root_state = self._find_state_by_id(path[0].from_state)
        root_url = root_state.url if root_state else state.url
        self._our_goto_active = True
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
            self._our_goto_active = False
        await asyncio.sleep(1.0)

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
                        page, wait_seconds=wait_s
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
                        self._our_goto_active = True
                        try:
                            await page.goto(
                                state.url, wait_until="domcontentloaded"
                            )
                        finally:
                            self._our_goto_active = False
                        await asyncio.sleep(1.5)
                        return False
                # Let the page settle after gate resolution.
                await asyncio.sleep(1.0)

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
                    self._our_goto_active = True
                    try:
                        await page.goto(
                            state.url, wait_until="domcontentloaded"
                        )
                    finally:
                        self._our_goto_active = False
                    await asyncio.sleep(1.5)
                    return False
                # Wait for potential navigation or DOM mutation.
                try:
                    await page.wait_for_load_state(
                        "networkidle", timeout=3000
                    )
                except Exception:
                    pass
                await asyncio.sleep(0.5)
            # URL-based transitions (http_3xx, meta_refresh, js_location) are
            # already reflected in the current page URL — the browser followed
            # them automatically.  No explicit replay needed.
        return True

    # ------------------------------------------------------------------
    # Navigation + state creation
    # ------------------------------------------------------------------

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
        if self._replaying:
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
            self._our_goto_active = True
            response = await page.goto(url, wait_until="domcontentloaded")
            self._our_goto_active = False

            # Settle: let on-load JS execute briefly.
            await asyncio.sleep(1.5)

            # Read back any JS-location intercepts the init script collected.
            js_locations: list[dict] = await page.evaluate(
                "() => window.__ge_js_locations || []"
            )
            # Combine with any URLs intercepted by the route guard.
            js_locations += self._intercepted_urls
            self._intercepted_urls.clear()

            # Clear the stash so we don't re-read them for the next state.
            await page.evaluate("() => { window.__ge_js_locations = []; }")

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

        # --- determine final URL and any HTTP-redirect chain ----------------
        final_url = page.url
        redirect_chain: list[str] = []

        if response is not None:
            # Walk back through the request chain to detect 3xx redirects.
            req = response.request
            while req is not None:
                redirected_from = req.redirected_from
                if redirected_from is not None:
                    redirect_chain.append(redirected_from.url)
                    req = redirected_from
                else:
                    break

        # --- capture HTML and compute hash -----------------------------------
        html_str = await page.content()
        dom_hash = normalise_and_hash(html_str)

        state = State(
            target_id=self.target.id,  # type: ignore[union-attr]
            url=final_url,
            dom_hash=dom_hash,
            depth=depth,
        )

        # --- save artifacts --------------------------------------------------
        if self._capture_artifacts_flag:
            await self._save_artifacts(state, page, html_str, network_entries)

        return state

    # ------------------------------------------------------------------
    # Navigation guard (Playwright route interceptor)
    # ------------------------------------------------------------------

    async def _install_navigation_guard(self, page: Page) -> None:
        """Install a route handler that aborts JS-initiated navigations.

        Any *navigation* request that fires while ``self._our_goto_active``
        is ``False`` is considered page-initiated: we abort it and stash
        the URL so the BFS can create a ``js_location`` transition.
        """
        self._intercepted_urls.clear()

        async def _guard(route):
            if self._replaying:
                # During replay, let all navigations through — we are only
                # positioning the page and already clear intercepts afterwards.
                await route.continue_()
                return
            if route.request.is_navigation_request():
                if not self._our_goto_active:
                    self._intercepted_urls.append(
                        {"url": route.request.url, "method": "href_setter"}
                    )
                    await route.abort()
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

        # --- js_location (from init script) --------------------------------
        # These were read back and cleared in _navigate_and_create_state().
        # We don't re-read them here — they are per-navigation.

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
    ) -> Optional[State]:
        """Click *action*'s element and detect navigation/DOM change.

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
            # never changed (SPA, multi-step forms).
            await self._replay_to_state(new_page, from_state)

            # Pre-click snapshot.
            pre_html = await new_page.content()
            pre_hash = normalise_and_hash(pre_html)
            pre_url = new_page.url

            # Click.
            try:
                await new_page.click(selector, timeout=5000)
            except Exception:
                # Element not found / not clickable — not an error, just skip.
                return None

            # Wait for potential navigation.
            try:
                await new_page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass  # timeout is expected for pages that don't navigate

            # Let any in-flight DOM mutations settle.
            await asyncio.sleep(0.5)

            # Post-click snapshot.
            post_url = new_page.url
            post_html = await new_page.content()
            post_hash = normalise_and_hash(post_html)

            # --- no observable change → discard branch -----------------------
            if post_url.rstrip("/") == pre_url.rstrip("/") and post_hash == pre_hash:
                return None

            # --- build the new State from the current page state --------------
            # Belt-and-suspenders: during replay the flag is True and we must
            # never create State / Transition objects.
            if self._replaying:
                return None

            new_state = State(
                target_id=self.target.id,  # type: ignore[union-attr]
                url=post_url,
                dom_hash=post_hash,
                depth=from_state.depth + 1,
            )

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
            self.transitions.append(transition)
            return new_state

        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=from_state.id,
                message=f"Click action error ({selector}): {exc}",
            )
            return None
        finally:
            await new_page.close()

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    async def _execute_action(
        self,
        page: Page,
        context: BrowserContext,
        from_state: State,
        action: dict,
    ) -> Optional[State]:
        """Execute *action*, record a Transition, return the new State (if any)."""
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
            self.transitions.append(transition)
            return new_state

        except Exception as exc:
            self._record_error(
                scope=EvidenceScope.state,
                scope_id=from_state.id,
                message=f"Action execution error ({kind_str} → {target_url}): {exc}",
            )
            return None
        finally:
            await new_page.close()

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
                "postData": request.post_data,
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
                "creator": {"name": "IVX-GraphEngine", "version": "0.1.0"},
                "pages": [{
                    "id": "page_1",
                    "title": page_url,
                    "startedDateTime": har_entries[0]["startedDateTime"] if har_entries else datetime.now(timezone.utc).isoformat(),
                }],
                "entries": har_entries,
            }
        }

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
            await page.screenshot(path=str(screenshot_path), full_page=True)
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
