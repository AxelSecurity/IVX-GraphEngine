"""Test per il runner della pipeline L0→L5."""

from __future__ import annotations

import uuid

import pytest

from graph_engine.models import AnalysisTarget, EvidenceScope, TargetStatus
from graph_engine.storage.repository import get_target_by_id, save_target

# ---------------------------------------------------------------------------
# Gli esploratori fake sono in conftest.py (FakeExplorer,
# ExplodingAfterExplorer, ecc.) — qui importiamo solo quello che serve
# per i test che NON usano il monkeypatch globale.
# ---------------------------------------------------------------------------

# Esploratore che viene creato MA popola zero stati (simula fallimento
# durante la costruzione dell'esploratore stesso, prima che run() venga
# chiamato — utile per testare il ramo "explorer is None").
class _ExplodingImmediatelyExplorer:
    """StateGraphExplorer finto che esplode appena costruito (run non
    verrà mai chiamato).  Simula un errore in L0/L1/L2."""

    def __init__(self, browser):
        self.browser = browser
        self.states = []
        self.transitions = []
        self.evidence = []
        self.target = None

    async def run(self, *args, **kwargs):
        raise RuntimeError("Boom! Should never be called")


class TestPipelineRunner:
    """Test per ``run_full_analysis`` — standalone e con target pre-creato."""

    async def test_run_full_analysis_persists_done(self, tmp_path, fake_pipeline):
        """Chiamata standalone: crea target, esegue pipeline, salva done.

        Verifica che explorer.target.id sia uguale ad analysis_target.id
        fin dall'inizio — senza riscritture successive (nessun _reparent).
        """
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
        # Lo state DEVE avere target_id uguale al target stesso
        # (nessuna riscrittura successiva — il target_id è stato iniettato)
        assert str(data["states"][0].target_id) == target_id
        # Classificazione fake → verdict presente
        assert data["verdict"] is not None
        assert data["verdict"].classification.value == "suspicious"
        assert data["verdict"].confidence == 0.5

    async def test_run_full_analysis_persists_error(
        self, tmp_path, fake_pipeline, monkeypatch,
    ):
        """Se l'esploratore esplode PRIMA di produrre stati, il target
        viene segnato error con solo la pipeline_error evidence."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            _ExplodingImmediatelyExplorer,
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

    # ── NUOVO TEST: sopravvivenza stati parziali su errore ──────────────

    async def test_partial_states_survive_on_l5_failure(
        self, tmp_path, fake_pipeline, monkeypatch,
    ):
        """Se L4 produce 3 stati con successo ma L5 esplode, i 3 stati
        DEVONO sopravvivere nel DB nonostante lo status finale sia "error".

        Questo test era IMPOSSIBILE prima del refactor target_id: il
        vecchio _reparent() richiedeva che l'esplorazione arrivasse fino
        in fondo per riscrivere gli UUID; un fallimento a metà lasciava
        gli stati con UUID orfani (FK constraint violato).  Ora che il
        target_id viene iniettato in explorer.run(), tutti i record figli
        nascono già con l'UUID API corretto.
        """
        from graph_engine.api.pipeline_runner import run_full_analysis

        # Usiamo ExplodingAfterExplorer dal conftest: popola 3 stati e POI esplode
        from tests.graph_engine.test_api.conftest import ExplodingAfterExplorer

        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            ExplodingAfterExplorer,
        )

        db = str(tmp_path / "test.db")

        # Pre-crea il target (pattern POST /analyses)
        target = AnalysisTarget(input_url="https://partial.example.com")
        target_id = str(target.id)
        await save_target(target, [], [], [], None, db_path=db)

        with pytest.raises(RuntimeError, match="L5 classification exploded"):
            await run_full_analysis(
                "https://partial.example.com",
                db_path=db,
                target=target,
                classify=True,
            )

        # VERIFICA: il target deve essere "error"
        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.error

        # VERIFICA: i 3 stati DEVONO sopravvivere
        assert len(data["states"]) == 3, (
            f"Expected 3 partial states to survive, got {len(data['states'])}"
        )

        # VERIFICA: ogni stato ha il target_id corretto (nessun UUID orfano)
        for s in data["states"]:
            assert str(s.target_id) == target_id, (
                f"State {s.id} has target_id {s.target_id}, expected {target_id}"
            )

        # VERIFICA: il depth degli stati è corretto (0, 1, 2)
        depths = sorted(s.depth for s in data["states"])
        assert depths == [0, 1, 2], f"Expected depths [0,1,2], got {depths}"

        # VERIFICA: la pipeline_error evidence è presente
        error_evs = [
            e for e in data["evidence"] if e.key == "pipeline_error"
        ]
        assert len(error_evs) == 1
        assert "L5 classification exploded" in error_evs[0].value
