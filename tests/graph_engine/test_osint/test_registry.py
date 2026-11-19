"""Tests per il registro provider di reputazione.

Il motore non ha provider di reputazione attivi: MISP, OpenCTI e
URLhaus sono gestiti a monte dal servizio chiamante.  Il registro resta
come punto di estensione per eventuali provider futuri.
"""

from __future__ import annotations

from graph_engine.osint.reputation.registry import get_enabled_providers


class TestRegistry:
    def test_no_providers_enabled(self):
        assert get_enabled_providers() == []
