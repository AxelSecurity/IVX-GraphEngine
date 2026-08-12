"""Fixture condivise per i test del wrapper Trellix."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.api.app import create_app


@pytest.fixture
def app(tmp_path):
    """App FastAPI con db isolato in tmp_path."""
    return create_app(
        db_path=str(tmp_path / "test.db"),
        artifact_root=tmp_path / "artifacts",
    )


@pytest.fixture
async def client(app):
    """Client httpx con ASGITransport."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
