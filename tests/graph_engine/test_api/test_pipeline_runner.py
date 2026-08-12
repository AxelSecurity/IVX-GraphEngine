"""Test per il runner della pipeline L0→L5."""

from __future__ import annotations

import pytest

from graph_engine.models import AnalysisTarget, TargetStatus
from graph_engine.storage.repository import get_target_by_id, save_target


# ---------------------------------------------------------------------------
# Fake esploratore che esplode — per test del path errore
# ---------------------------------------------------------------------------


class _ExplodingExplorer:
    """StateGraphExplorer finto che lancia RuntimeError in run()."""

    def __init__(self, browser):
        self.browser = browser
        self.states = []
        self.transitions = []
        self.evidence = []
        self.target = None

    async def run(self, *args, **kwargs):
        raise RuntimeError("Boom! Simulated explorer failure")


class TestPipelineRunner:
    """Test per ``run_full_analysis`` — standalone e con target pre-creato."""

    async def test_run_full_analysis_persists_done(self, tmp_path, fake_pipeline):
        """Chiamata standalone: crea target, esegue pipeline, salva done."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        db = str(tmp_path / "test.db")
        target_id = await run_full_analysis(
            "https://example.com/login",
            db_path=db,
            classify=True,
        )

        data = await get_target_by_id(target_id, db_path=db)
        assert data is not None
        assert data["target"].status == TargetStatus.done
        # url_hash deve essere popolato da ingest() reale
        assert data["target"].url_hash is not None
        assert len(data["target"].url_hash) == 64  # SHA-256
        # Deve esserci almeno uno stato (quello creato da FakeExplorer)
        assert len(data["states"]) == 1
        # Classificazione fake → verdict presente
        assert data["verdict"] is not None
        assert data["verdict"].classification.value == "suspicious"
        assert data["verdict"].confidence == 0.5

    async def test_run_full_analysis_persists_error(
        self, tmp_path, fake_pipeline, monkeypatch,
    ):
        """Se l'esploratore esplode, il target viene segnato error."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            _ExplodingExplorer,
        )

        db = str(tmp_path / "test.db")

        # Creiamo un target pre-esistente così conosciamo l'ID
        target = AnalysisTarget(input_url="https://example.com")
        target_id = str(target.id)
        await save_target(target, [], [], [], None, db_path=db)

        with pytest.raises(RuntimeError, match="Boom"):
            await run_full_analysis(
                "https://example.com",
                db_path=db,
                target=target,
                classify=False,
            )

        # Dopo l'errore, il target DEVE essere stato salvato come error
        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.error
        # Deve esserci la pipeline_error evidence
        error_evs = [
            e for e in data["evidence"] if e.key == "pipeline_error"
        ]
        assert len(error_evs) == 1
        assert "RuntimeError" in error_evs[0].value
        assert "Boom" in error_evs[0].value

    async def test_run_full_analysis_with_precreated_target(
        self, tmp_path, fake_pipeline,
    ):
        """Con target pre-creato (pattern POST /analyses), l'UUID è
        noto prima che la pipeline parta e viene conservato."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        db = str(tmp_path / "test.db")

        # Simula il pattern della route POST:
        # 1. Crea e salva "queued"
        target = AnalysisTarget(input_url="https://example.com")
        await save_target(target, [], [], [], None, db_path=db)
        pre_created_id = str(target.id)

        # 2. Chiama run_full_analysis con target=...
        result_id = await run_full_analysis(
            "https://example.com",
            db_path=db,
            target=target,
            classify=False,
        )

        # L'id restituito DEVE essere lo stesso pre-creato
        assert result_id == pre_created_id

        # 3. Il target deve essere "done"
        data = await get_target_by_id(result_id, db_path=db)
        assert data["target"].status == TargetStatus.done
        # I campi L0 devono essere stati patchati
        assert data["target"].canonical_url is not None
        assert data["target"].url_hash is not None
