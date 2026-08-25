"""Test di regressione: serializzazione dict/list in ``Evidence.value``.

Caso reale: ``rinnovospid.cc/pay`` — crt.sh ha risposto HTTP 404 e
l'analyzer osint ha prodotto un'evidence ``provider_unavailable`` con
``value`` dict.  Prima della fix, i loop di registrazione in ``cli.py``
passavano il dict direttamente a ``Evidence`` (``value: str``) →
``ValidationError`` → crash dell'intera esplorazione.

Questo test esegue ``cli._main`` end-to-end con tutti gli stage di rete
mocked e verifica che il value diventi una stringa JSON deserializzabile
che restituisce il dict originale.
"""

from __future__ import annotations

import argparse
import json

from tests.graph_engine.test_api.conftest import FakeExplorer, FakePlaywright


CRTSH_ERROR = {
    "provider": "crtsh",
    "reason": "crt.sh HTTP error: 404 Not Found",
}


class _RecordingExplorer(FakeExplorer):
    """FakeExplorer che registra ogni istanza per ispezione post-run."""

    instances: list[_RecordingExplorer] = []

    def __init__(self, browser):
        super().__init__(browser)
        self.__class__.instances.append(self)


class TestCliEvidenceSerialization:
    """Il value dict di L2 deve diventare una stringa JSON, non un crash."""

    async def test_dict_evidence_value_does_not_raise(self, monkeypatch):
        """_main con analyzer osint che restituisce un value dict → nessun
        ValidationError e il value registrato è JSON deserializzabile."""
        from graph_engine.cli import _main

        _RecordingExplorer.instances = []

        monkeypatch.setattr(
            "graph_engine.cli.async_playwright", FakePlaywright
        )
        monkeypatch.setattr(
            "graph_engine.cli.StateGraphExplorer", _RecordingExplorer
        )

        # L1 è sync — la CLI NON la awaita
        monkeypatch.setattr(
            "graph_engine.lexical.analyzer.analyze",
            lambda url, payloads: {"evidence": [], "lexical_risk_score": 0.0},
        )

        async def _fake_l2(url):
            """Simula il caso reale: crt.sh 404 → provider_unavailable dict."""
            return {
                "evidence": [
                    {
                        "layer": "L2",
                        "key": "provider_unavailable",
                        "value": CRTSH_ERROR,
                        "weight": 0.0,
                        "produced_by": "osint",
                    }
                ],
                "passive_risk_score": 0.0,
            }

        async def _fake_l3(url):
            return {"evidence": [], "recommended_profile": {}}

        monkeypatch.setattr("graph_engine.osint.analyzer.analyze", _fake_l2)
        monkeypatch.setattr("graph_engine.active.analyzer.analyze", _fake_l3)

        # Non scrivere il DB reale
        async def _noop_save(*args, **kwargs):
            pass

        monkeypatch.setattr(
            "graph_engine.storage.repository.save_target", _noop_save
        )

        args = argparse.Namespace(
            url="https://rinnovospid.cc/pay",
            max_depth=2,
            max_nodes=4,
            timeout=30,
            no_artifacts=True,
            top_n_actions=0,
            settle_max_wait=4.0,
            classify=False,
        )

        # Prima della fix: ValidationError su Evidence.value (dict su str)
        await _main(args)

        explorer = _RecordingExplorer.instances[-1]
        l2_evs = [e for e in explorer.evidence if e.layer == "L2"]
        assert len(l2_evs) == 1
        stored = l2_evs[0].value
        assert isinstance(stored, str), (
            f"Evidence.value deve essere str, trovato {type(stored).__name__}"
        )
        assert json.loads(stored) == CRTSH_ERROR
