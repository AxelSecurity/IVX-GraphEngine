"""Test per il runner della pipeline L0→L5."""

from __future__ import annotations

import uuid

import pytest

from graph_engine.api.pipeline_runner import (
    _run_classification as _REAL_RUN_CLASSIFICATION,
)
from graph_engine.models import (
    AnalysisTarget,
    Classification,
    EvidenceScope,
    State,
    TargetStatus,
    Verdict,
)
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

    def __init__(self, browser, **kwargs):
        # **kwargs: il runner passa page_timeout_ms al costruttore —
        # il fake lo accetta e lo ignora.
        self.browser = browser
        self.states = []
        self.transitions = []
        self.evidence = []
        self.target = None

    async def run(self, *args, **kwargs):
        raise RuntimeError("Boom! Should never be called")


class _RecordingExplorer:
    """StateGraphExplorer finto che registra i parametri ricevuti dal
    runner (costruttore e run) — per verificare il plumb dei parametri
    fast di L4 (settle_max_wait_s, page_timeout_ms)."""

    init_kwargs: dict = {}
    run_kwargs: dict = {}

    def __init__(self, browser, **kwargs):
        type(self).init_kwargs = kwargs
        self.browser = browser

    async def run(self, start_url, **kwargs):
        type(self).run_kwargs = kwargs
        tid = kwargs.get("target_id")
        self.target = AnalysisTarget(
            id=tid if tid is not None else uuid.uuid4(),
            input_url=start_url,
            final_url=start_url,
            status=TargetStatus.done,
        )
        root = State(
            target_id=self.target.id,
            url=start_url,
            dom_hash="h0",
            depth=0,
        )
        self.target.root_state_id = root.id
        self.states = [root]
        self.transitions = []
        self.evidence = []
        return self.target


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

    async def test_dict_evidence_value_serialized_before_persist(
        self, fake_pipeline, tmp_path, monkeypatch
    ):
        """L2 che restituisce un value dict (caso reale: provider CT in
        errore HTTP 404) → nessun ValidationError e il value salvato su
        SQLite è una stringa JSON che round-trip sul dict originale."""
        import json

        from graph_engine.api.pipeline_runner import run_full_analysis

        ctlogs_error = {
            "provider": "ctlogs.dev",
            "reason": "ctlogs.dev HTTP error: 404",
        }

        async def _fake_l2_with_dict(url, timeout_s=None):
            return {
                "evidence": [
                    {
                        "layer": "L2",
                        "key": "provider_unavailable",
                        "value": ctlogs_error,
                        "weight": 0.0,
                        "produced_by": "osint",
                    }
                ],
                "passive_risk_score": 0.0,
            }

        # Sovrascrive il mock "evidence vuote" del fixture fake_pipeline
        monkeypatch.setattr(
            "graph_engine.osint.analyzer.analyze",
            _fake_l2_with_dict,
        )

        db = str(tmp_path / "test.db")
        target_id = await run_full_analysis(
            "https://rinnovospid.cc/pay",
            db_path=db,
            classify=False,
        )

        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.done

        l2_evs = [
            e for e in data["evidence"] if e.key == "provider_unavailable"
        ]
        assert len(l2_evs) == 1
        stored = l2_evs[0].value
        assert isinstance(stored, str), (
            f"Evidence.value su SQLite deve essere str, "
            f"trovato {type(stored).__name__}"
        )
        assert json.loads(stored) == ctlogs_error

    async def test_l2_and_l3_run_in_parallel(
        self, fake_pipeline, tmp_path, monkeypatch
    ):
        """Handshake deterministico: L3 termina subito e L2 aspetta un
        release che il test concede SOLO dopo aver visto L3 finire.

        Se il runner eseguisse L2 e L3 in sequenza (L2 prima), L2
        resterebbe bloccato in attesa del release → ``wait_for`` scadrebbe
        e il target andrebbe in error prima ancora che L3 venga chiamato:
        il test fallirebbe sul ``l3_done`` che non scatta mai.
        """
        import asyncio

        from graph_engine.api.pipeline_runner import run_full_analysis

        l3_done = asyncio.Event()
        release_l2 = asyncio.Event()

        async def _handshake_l2(url, timeout_s=None):
            # 3s di margine: se L2 girasse PRIMA di L3, esploderebbe qui
            # per timeout ben prima del wait_for esterno del test.
            await asyncio.wait_for(release_l2.wait(), timeout=3.0)
            return {"evidence": [], "passive_risk_score": 0.0}

        async def _handshake_l3(url, timeout_s=None, profile_probe=None):
            l3_done.set()
            return {"evidence": [], "recommended_profile": {}}

        monkeypatch.setattr(
            "graph_engine.osint.analyzer.analyze", _handshake_l2
        )
        monkeypatch.setattr(
            "graph_engine.active.analyzer.analyze", _handshake_l3
        )

        db = str(tmp_path / "test.db")
        task = asyncio.create_task(
            run_full_analysis(
                "https://example.com",
                db_path=db,
                classify=False,
            )
        )

        # Prova che L3 è partito senza aspettare la fine di L2
        await asyncio.wait_for(l3_done.wait(), timeout=2.0)
        release_l2.set()

        target_id = await asyncio.wait_for(task, timeout=5.0)
        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.done

    async def test_fast_l4_params_forwarded_to_explorer(
        self, fake_pipeline, tmp_path, monkeypatch
    ):
        """Plumb fast L4: ``page_timeout_ms`` deve arrivare al costruttore
        di StateGraphExplorer e ``settle_max_wait_s`` a ``explorer.run()``
        (parametri usati dai chiamanti con budget personalizzato)."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        _RecordingExplorer.init_kwargs = {}
        _RecordingExplorer.run_kwargs = {}

        monkeypatch.setattr(
            "graph_engine.explorer.StateGraphExplorer",
            _RecordingExplorer,
        )

        db = str(tmp_path / "test.db")
        await run_full_analysis(
            "https://example.com",
            db_path=db,
            classify=False,
            settle_max_wait_s=3.0,
            page_timeout_ms=15000,
        )

        assert _RecordingExplorer.init_kwargs == {"page_timeout_ms": 15000}
        assert _RecordingExplorer.run_kwargs["settle_max_wait_s"] == 3.0


class TestL4StartsAfterProfileProbe:
    """L4 parte appena il profilo (differential fetch) è pronto: L2 e il
    resto di L3 corrono IN PARALLELO all'esplorazione."""

    async def test_l4_runs_while_l2_and_l3_are_still_running(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Handshake deterministico: L2 e L3 terminano SOLO dopo che L4
        è partito.  Con l'orchestrazione sequenziale (L2/L3 prima di L4)
        il test va in deadlock e scade il timeout."""
        import asyncio

        from graph_engine.api.pipeline_runner import run_full_analysis
        from tests.graph_engine.test_api.conftest import FakeExplorer

        l4_started = asyncio.Event()

        class _SignallingExplorer(FakeExplorer):
            async def run(self, *args, **kwargs):
                l4_started.set()
                return await super().run(*args, **kwargs)

        async def _l2_waits_for_l4(url, timeout_s=None):
            await l4_started.wait()
            return {"evidence": [], "passive_risk_score": 0.0}

        async def _l3_waits_for_l4(url, timeout_s=None, profile_probe=None):
            await l4_started.wait()
            return {"evidence": [], "recommended_profile": {}}

        monkeypatch.setattr("graph_engine.explorer.StateGraphExplorer", _SignallingExplorer)
        monkeypatch.setattr("graph_engine.osint.analyzer.analyze", _l2_waits_for_l4)
        monkeypatch.setattr("graph_engine.active.analyzer.analyze", _l3_waits_for_l4)

        db = str(tmp_path / "test.db")
        target_id = await asyncio.wait_for(
            run_full_analysis("https://example.com", db_path=db, classify=False),
            timeout=5.0,
        )
        data = await get_target_by_id(target_id, db_path=db)
        assert data["target"].status == TargetStatus.done

    async def test_l4_receives_probe_profiles_and_l3_reuses_probe(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Il profilo e il ramo cloaking arrivano a L4 dalla sonda; L3
        riceve lo STESSO task (nessun secondo differential fetch)."""
        from graph_engine.api.pipeline_runner import run_full_analysis

        probe_calls = []
        seen_probe = []

        async def _probe(url):
            probe_calls.append(url)
            return {
                "diff_result": None,
                "cloaking": None,
                "recommended_profile": {"user_agent": "UA-probe"},
                "cloaking_profile": {"user_agent": "UA-cloak"},
            }

        async def _l3(url, timeout_s=None, profile_probe=None):
            seen_probe.append(profile_probe)
            await profile_probe
            return {"evidence": [], "recommended_profile": {}}

        _RecordingExplorer.run_kwargs = {}
        monkeypatch.setattr("graph_engine.explorer.StateGraphExplorer", _RecordingExplorer)
        monkeypatch.setattr("graph_engine.active.analyzer.probe_profile", _probe)
        monkeypatch.setattr("graph_engine.active.analyzer.analyze", _l3)

        await run_full_analysis(
            "https://example.com", db_path=str(tmp_path / "t.db"), classify=False,
        )

        assert len(probe_calls) == 1
        assert seen_probe and seen_probe[0] is not None
        assert _RecordingExplorer.run_kwargs["profile"] == {"user_agent": "UA-probe"}
        assert _RecordingExplorer.run_kwargs["cloaking_profile"] == {"user_agent": "UA-cloak"}

    async def test_l4_failure_cancels_pending_l2_l3(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        """Se L4 esplode, i task L2/L3 ancora in volo vengono cancellati
        (nessun lavoro di rete orfano) e il target va in error."""
        import asyncio

        from graph_engine.api.pipeline_runner import run_full_analysis

        cancelled = asyncio.Event()

        async def _l2_hangs(url, timeout_s=None):
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return {"evidence": [], "passive_risk_score": 0.0}

        class _ExplodingRun(_ExplodingImmediatelyExplorer):
            pass

        monkeypatch.setattr("graph_engine.osint.analyzer.analyze", _l2_hangs)
        monkeypatch.setattr("graph_engine.explorer.StateGraphExplorer", _ExplodingRun)

        db = str(tmp_path / "test.db")
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(
                run_full_analysis("https://example.com", db_path=db, classify=False),
                timeout=5.0,
            )
        assert cancelled.is_set()


class TestFormFieldsReachClassifier:
    """L'inventario dei campi form raccolto da L4 arriva al bundle L5
    (prima ogni stato arrivava con form_fields=[])."""

    async def test_explorer_form_fields_forwarded(
        self, fake_pipeline, tmp_path, monkeypatch,
    ):
        from graph_engine.api import pipeline_runner
        from tests.graph_engine.test_api.conftest import FakeExplorer

        fields = [{"tag": "input", "type": "password", "name_or_id": "pwd",
                   "nearby_label_text": "Password"}]

        class _FormExplorer(FakeExplorer):
            async def run(self, *args, **kwargs):
                target = await super().run(*args, **kwargs)
                self.form_fields_by_state = {
                    str(st.id): fields for st in self.states
                }
                return target

        captured = {}

        async def _capture_bundle(**kwargs):
            captured.update(kwargs)
            return {"states": [], "flags": {}, "evidence_summary": {}}

        monkeypatch.setattr("graph_engine.explorer.StateGraphExplorer", _FormExplorer)
        # La fixture sostituisce _run_classification: qui serve quella vera.
        monkeypatch.setattr(
            pipeline_runner, "_run_classification", _REAL_RUN_CLASSIFICATION,
        )
        monkeypatch.setattr(
            "graph_engine.classifier.evidence_bundle.build_evidence_bundle",
            _capture_bundle,
        )
        monkeypatch.setattr(
            "graph_engine.classifier.prefilter.prefilter",
            lambda bundle: Verdict(
                target_id=bundle["target_id"],
                classification=Classification.benign,
                confidence=0.9,
                produced_by="prefilter",
            ),
        )

        await pipeline_runner.run_full_analysis(
            "https://example.com", db_path=str(tmp_path / "t.db"), classify=True,
        )

        by_state = captured["form_fields_by_state"]
        assert by_state, "nessuno stato nel bundle"
        assert all(v == fields for v in by_state.values())
