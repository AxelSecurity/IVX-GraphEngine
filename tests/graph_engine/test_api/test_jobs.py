"""Test per il registro dei job (``graph_engine.api.jobs``)."""

from __future__ import annotations

import asyncio

from graph_engine.api.jobs import AnalysisJobs
from graph_engine.models import AnalysisTarget


class TestAnalysisJobs:
    async def test_concurrency_limit_respected(self, monkeypatch):
        """Mai più di ``max_concurrent`` pipeline in esecuzione."""
        active = 0
        peak = 0
        gate = asyncio.Event()

        async def _pipeline(*args, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await gate.wait()
            active -= 1
            return str(kwargs["target"].id)

        monkeypatch.setattr("graph_engine.api.jobs.run_full_analysis", _pipeline)
        jobs = AnalysisJobs(max_concurrent=2)
        tasks = [
            jobs.start("https://e.example", AnalysisTarget(input_url="https://e.example"))
            for _ in range(5)
        ]
        await asyncio.sleep(0.05)
        assert active == 2
        assert jobs.running_count == 5  # 3 in attesa dello slot

        gate.set()
        await asyncio.gather(*tasks)
        assert peak == 2
        assert jobs.running_count == 0

    async def test_inflight_registered_until_done(self, monkeypatch):
        """Il task è visibile per url_hash finché gira, poi sparisce."""
        gate = asyncio.Event()

        async def _pipeline(*args, **kwargs):
            await gate.wait()
            return "x"

        monkeypatch.setattr("graph_engine.api.jobs.run_full_analysis", _pipeline)
        jobs = AnalysisJobs(max_concurrent=1)
        target = AnalysisTarget(input_url="https://e.example")
        task = jobs.start("https://e.example", target, url_hash="h1")

        entry = jobs.inflight("h1")
        assert entry is not None
        assert entry[0] == str(target.id)
        assert entry[1] is task
        assert jobs.inflight("other") is None

        gate.set()
        await task
        await asyncio.sleep(0)
        assert jobs.inflight("h1") is None

    async def test_failed_task_cleared_and_logged(self, monkeypatch):
        """Un fallimento non lascia il task registrato né solleva
        'Task exception was never retrieved'."""

        async def _pipeline(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr("graph_engine.api.jobs.run_full_analysis", _pipeline)
        jobs = AnalysisJobs(max_concurrent=1)
        task = jobs.start(
            "https://e.example", AnalysisTarget(input_url="https://e.example"),
            url_hash="h2",
        )
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)
        assert jobs.inflight("h2") is None
        assert jobs.running_count == 0
