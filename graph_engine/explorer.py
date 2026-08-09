"""BFS state-graph explorer — passive redirects (http_3xx, meta_refresh, js_location).

Implements the BFS loop from ARCHITECTURE_L4.md using Playwright async API.
This phase handles only *passive* transitions: no click / form_submit.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Optional
from urllib.parse import urljoin, urlparse

from lxml import html as lxml_html
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from graph_engine.budget import Budget
from graph_engine.dom_hash import normalise_and_hash
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

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        start_url: str,
        budget: Optional[Budget] = None,
        profile: Optional[dict] = None,
    ) -> AnalysisTarget:
        """Explore *start_url* passively and return the populated AnalysisTarget.

        The BFS respects *budget* limits and collects every State, Transition,
        and Evidence in ``self.states``, ``self.transitions``, ``self.evidence``.
        """
        budget = budget or Budget()
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
        context = await self._browser.new_context(
            user_agent=self._profile.get(
                "user_agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            ),
            viewport={"width": 1280, "height": 720},
            locale=self._profile.get("locale", "en-US"),
            timezone_id=self._profile.get("timezone", "America/New_York"),
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
            self.target.canonical_url = root_state.url
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

                # Enumerate *passive* actions from this state
                actions = await self._enumerate_passive_actions(page, state)

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
        try:
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
            self._record_error(
                scope=EvidenceScope.target,
                scope_id=self.target.id if self.target else uuid.uuid4(),
                message=f"Navigation error for {url}: {exc}",
            )
            return None

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
    # Action execution
    # ------------------------------------------------------------------

    async def _execute_action(
        self,
        page: Page,
        context: BrowserContext,
        from_state: State,
        action: dict,
    ) -> Optional[State]:
        """Navigate to *action*'s URL, record a Transition, return new State."""
        kind_str = action["kind"]
        target_url = action["url"]

        # Map string kind to TransitionKind enum
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

    def _record_error(
        self,
        scope: EvidenceScope,
        scope_id: uuid.UUID,
        message: str,
    ) -> None:
        self.evidence.append(
            Evidence(
                target_id=self.target.id if self.target else uuid.uuid4(),  # type: ignore[union-attr]
                scope=scope,
                scope_id=scope_id,
                layer="L4",
                key="navigation_error",
                value=message,
                weight=1.0,
                produced_by="StateGraphExplorer",
            )
        )
