"""Tests for per-state artifact capture — HAR, screenshot, DOM snapshot."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph_engine.explorer import StateGraphExplorer
from graph_engine.models import State


# ---------------------------------------------------------------------------
# Unit — verify refs and file creation via _save_artifacts directly
# ---------------------------------------------------------------------------


class TestArtifactSave:
    """Exercise _save_artifacts with a mocked page — fast, no browser."""

    async def test_three_files_created_and_refs_set(self, tmp_path: Path):
        """All three artifacts are written and State refs are populated."""
        explorer = StateGraphExplorer(MagicMock())
        explorer._artifact_base = tmp_path / "artifacts"

        # We need a plausible target.id for the path.
        target_id = uuid.uuid4()
        explorer.target = MagicMock()
        explorer.target.id = target_id

        state = State(
            target_id=target_id,
            url="https://example.com",
            dom_hash="abc123def456",
            depth=0,
        )

        # Mock page: screenshot writes a real (tiny) PNG on disk.
        page = AsyncMock()

        async def _fake_screenshot(*, path: str, full_page: bool):
            Path(path).write_bytes(
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
                b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
                b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
                b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
            )

        page.screenshot = AsyncMock(side_effect=_fake_screenshot)

        html = "<html><head><title>Example</title></head><body><p>Hello</p></body></html>"
        network_entries = [
            {
                "url": "https://example.com",
                "method": "GET",
                "headers": {"Host": "example.com"},
                "postData": None,
                "startedDateTime": "2025-01-01T00:00:00Z",
                "_start_ms": 0.0,
                "response_status": 200,
                "response_statusText": "OK",
                "response_headers": {"Content-Type": "text/html"},
                "time_ms": 350,
            }
        ]

        await explorer._save_artifacts(state, page, html, network_entries)

        # --- refs are relative paths -----------------------------------------
        assert state.screenshot_ref is not None
        assert state.har_ref is not None
        assert "screenshot.png" in state.screenshot_ref
        assert "snapshot.har" in state.har_ref

        # --- directory -------------------------------------------------------
        expected_dir = (
            tmp_path / "artifacts" / str(target_id) / str(state.id)
        )
        assert expected_dir.is_dir()

        # --- screenshot.png --------------------------------------------------
        screenshot = expected_dir / "screenshot.png"
        assert screenshot.is_file()
        assert screenshot.stat().st_size > 0

        # --- dom.html --------------------------------------------------------
        dom_file = expected_dir / "dom.html"
        assert dom_file.is_file()
        saved_html = dom_file.read_text(encoding="utf-8")
        assert saved_html == html
        assert "Example" in saved_html

        # --- snapshot.har ----------------------------------------------------
        har_file = expected_dir / "snapshot.har"
        assert har_file.is_file()
        har_raw = har_file.read_text(encoding="utf-8")
        assert "Example" not in har_raw  # HAR is JSON, not HTML
        assert '"version"' in har_raw
        assert '"1.2"' in har_raw
        assert har_file.stat().st_size > 0


class TestCaptureFlag:
    """Verify capture_artifacts flag behaviour in run()."""

    @patch("graph_engine.explorer.asyncio.sleep", new_callable=AsyncMock)
    async def test_capture_disabled_refs_remain_none(self, mock_sleep):
        """When capture_artifacts=False, no artifacts are saved and refs stay None."""
        from graph_engine.budget import Budget
        from graph_engine.models import TargetStatus

        page = AsyncMock()
        page.url = "https://example.com"
        page.content = AsyncMock(return_value="<html><body>test</body></html>")

        mock_resp = AsyncMock()
        mock_req = AsyncMock()
        mock_req.redirected_from = None
        mock_resp.request = mock_req
        page.goto = AsyncMock(return_value=mock_resp)

        page.evaluate = AsyncMock(return_value=[])
        page.add_init_script = AsyncMock()
        page.route = AsyncMock()
        page.set_default_timeout = MagicMock()
        page.close = AsyncMock()

        context = AsyncMock()
        context.new_page = AsyncMock(return_value=page)
        context.close = AsyncMock()

        browser = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)

        explorer = StateGraphExplorer(browser)
        target = await explorer.run(
            "https://example.com",
            budget=Budget(max_nodes=1, max_depth=0, timeout_s=60),
            capture_artifacts=False,
        )

        assert target.status == TargetStatus.done
        assert len(explorer.states) == 1
        state = explorer.states[0]
        assert state.screenshot_ref is None
        assert state.har_ref is None


# ---------------------------------------------------------------------------
# Integration — real browser against example.com
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestArtifactIntegration:
    async def test_example_com_creates_artifacts(self, tmp_path: Path):
        """Explore example.com with capture enabled — files must exist and be non-empty."""
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                explorer = StateGraphExplorer(browser)
                explorer._artifact_base = tmp_path / "artifacts"

                from graph_engine.budget import Budget
                target = await explorer.run(
                    "https://example.com",
                    budget=Budget(max_depth=0, max_nodes=1, timeout_s=60),
                    capture_artifacts=True,
                )

                assert len(explorer.states) == 1
                state = explorer.states[0]

                # Refs are set
                assert state.screenshot_ref is not None
                assert state.har_ref is not None

                # Files exist on disk
                expected_dir = (
                    tmp_path
                    / "artifacts"
                    / str(target.id)
                    / str(state.id)
                )
                assert expected_dir.is_dir()

                screenshot = expected_dir / "screenshot.png"
                assert screenshot.is_file()
                assert screenshot.stat().st_size > 0

                dom = expected_dir / "dom.html"
                assert dom.is_file()
                dom_text = dom.read_text(encoding="utf-8")
                assert "Example" in dom_text or "example" in dom_text.lower()

                har = expected_dir / "snapshot.har"
                assert har.is_file()
                har_text = har.read_text(encoding="utf-8")
                assert '"version"' in har_text
                assert har.stat().st_size > 0

            finally:
                await browser.close()
