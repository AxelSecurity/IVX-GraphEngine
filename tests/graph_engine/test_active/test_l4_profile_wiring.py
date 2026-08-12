"""Test per il wiring L4: profile → browser.new_context().

Verifica che ``StateGraphExplorer.run(profile={...})`` passi davvero
user_agent e headers alla creazione del context Playwright.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest


class TestL4ProfileWiring:
    """Verifica che il profilo L3 venga passato correttamente a Playwright."""

    async def test_user_agent_passed_to_new_context(self):
        """User-Agent dal profile viene passato a browser.new_context()."""
        from graph_engine.explorer import StateGraphExplorer

        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)

        # Mocka _navigate_and_create_state per evitare l'esecuzione reale
        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            return_value=None,
        ):
            explorer = StateGraphExplorer(browser)
            custom_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"

            await explorer.run(
                "https://example.com",
                profile={
                    "user_agent": custom_ua,
                    "headers": {"Accept-Language": "it-IT"},
                },
            )

        # Verifica che new_context sia stato chiamato con user_agent corretto
        call_kwargs = browser.new_context.call_args
        assert call_kwargs is not None
        kwargs = call_kwargs[1]  # keyword arguments
        assert kwargs["user_agent"] == custom_ua

    async def test_extra_http_headers_passed_to_new_context(self):
        """Headers dal profile vengono passati come extra_http_headers."""
        from graph_engine.explorer import StateGraphExplorer

        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)

        custom_headers = {
            "Accept-Language": "it-IT,it;q=0.9",
            "Accept": "text/html,*/*;q=0.8",
        }

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            return_value=None,
        ):
            explorer = StateGraphExplorer(browser)

            await explorer.run(
                "https://example.com",
                profile={
                    "user_agent": "CustomBot/1.0",
                    "headers": custom_headers,
                },
            )

        call_kwargs = browser.new_context.call_args
        kwargs = call_kwargs[1]
        assert "extra_http_headers" in kwargs
        assert kwargs["extra_http_headers"] == custom_headers

    async def test_default_user_agent_when_no_profile(self):
        """Senza profile → user_agent default (Chrome)."""
        from graph_engine.explorer import StateGraphExplorer

        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            return_value=None,
        ):
            explorer = StateGraphExplorer(browser)

            await explorer.run("https://example.com")

        call_kwargs = browser.new_context.call_args
        kwargs = call_kwargs[1]
        assert "Chrome" in kwargs["user_agent"]
        # extra_http_headers deve essere None o assente
        assert kwargs.get("extra_http_headers") in (None, {})

    async def test_empty_headers_not_passed_as_extra(self):
        """Headers vuoti → extra_http_headers=None."""
        from graph_engine.explorer import StateGraphExplorer

        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            return_value=None,
        ):
            explorer = StateGraphExplorer(browser)

            await explorer.run(
                "https://example.com",
                profile={
                    "user_agent": "Test/1.0",
                    "headers": {},  # vuoto
                },
            )

        call_kwargs = browser.new_context.call_args
        kwargs = call_kwargs[1]
        assert kwargs.get("extra_http_headers") is None

    async def test_init_profile_used_when_run_profile_omitted(self):
        """Il profile passato a __init__ viene usato se run() non ne passa uno."""
        from graph_engine.explorer import StateGraphExplorer

        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)

        init_profile = {
            "user_agent": "InitAgent/1.0",
            "headers": {"X-Init": "true"},
        }

        with patch.object(
            StateGraphExplorer, "_navigate_and_create_state",
            return_value=None,
        ):
            explorer = StateGraphExplorer(browser, profile=init_profile)

            # run() senza profile esplicito → usa quello di __init__
            await explorer.run("https://example.com")

        call_kwargs = browser.new_context.call_args
        kwargs = call_kwargs[1]
        assert kwargs["user_agent"] == "InitAgent/1.0"
        assert kwargs["extra_http_headers"] == {"X-Init": "true"}
