"""Rate limit di Foundry: tentativi ripetuti e tetto di concorrenza."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from graph_engine.classifier import foundry_classifier as fc
from graph_engine.config import settings
from tests.graph_engine.test_classifier.test_foundry_classifier import (
    _FakeAgentsClient,
    _register_fake_azure_modules,
    _sample_bundle,
    _unregister_fake_azure_modules,
)


@pytest.fixture(autouse=True)
def _fast_retries(monkeypatch):
    """Niente attese reali: si registrano i ritardi richiesti."""
    delays: list[float] = []

    async def _fake_sleep(seconds):
        delays.append(seconds)

    monkeypatch.setattr(fc.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(fc.random, "uniform", lambda a, b: 0.0)
    fc._foundry_slots.clear()
    fc._reset_client_cache()
    yield delays
    fc._wait_for_cleanup(timeout=5)
    fc._reset_client_cache()


class TestRetryOnRateLimit:
    async def test_retries_then_succeeds(self, monkeypatch, _fast_retries):
        calls = 0

        async def _run(prompt):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise fc._FoundryRateLimited("rate_limit_exceeded")
            return '{"classification": "phishing", "confidence": 0.9}'

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        verdict = await fc.classify(_sample_bundle())

        assert calls == 3
        assert _fast_retries == [10.0, 20.0]  # attesa crescente
        assert verdict.produced_by == "foundry"
        assert verdict.classification.value == "phishing"

    async def test_uses_retry_after_from_azure(self, monkeypatch, _fast_retries):
        msg = "Rate limit exceeded. Please retry after 7 seconds."
        calls = 0

        async def _run(prompt):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise fc._FoundryRateLimited(msg, retry_after=fc._parse_retry_after(msg))
            return '{"classification": "benign", "confidence": 0.9}'

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        await fc.classify(_sample_bundle())
        assert _fast_retries == [7.0]

    async def test_gives_up_and_falls_back(self, monkeypatch, _fast_retries):
        async def _run(prompt):
            raise fc._FoundryRateLimited("rate_limit_exceeded")

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        verdict = await fc.classify(_sample_bundle())

        assert _fast_retries == [10.0, 20.0, 40.0]
        assert verdict.produced_by == "heuristic_fallback"

    async def test_http_429_is_retried(self, monkeypatch, _fast_retries):
        class _HttpError(Exception):
            status_code = 429
            response = SimpleNamespace(headers={"Retry-After": "4"})

        calls = 0

        async def _run(prompt):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise _HttpError("Too Many Requests")
            return '{"classification": "benign", "confidence": 0.9}'

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        verdict = await fc.classify(_sample_bundle())
        assert _fast_retries == [4.0]
        assert verdict.produced_by == "foundry"

    async def test_other_errors_not_retried(self, monkeypatch, _fast_retries):
        calls = 0

        async def _run(prompt):
            nonlocal calls
            calls += 1
            raise RuntimeError("Agent run failed: content_filter")

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        verdict = await fc.classify(_sample_bundle())
        assert calls == 1
        assert _fast_retries == []
        assert verdict.produced_by == "heuristic_fallback"


class TestFailedRunMapping:
    """Un run FAILED con last_error rate_limit_exceeded (il caso visto in
    produzione) viene riconosciuto e ritentato su un thread NUOVO."""

    async def test_failed_run_rate_limit_is_retried_with_new_thread(
        self, monkeypatch, _fast_retries,
    ):
        recorder = _FakeAgentsClient()
        outcomes = iter([
            SimpleNamespace(status="failed", last_error={
                "code": "rate_limit_exceeded",
                "message": "exceeded token rate limit. Please retry after 12 seconds.",
            }),
            SimpleNamespace(status="completed"),
        ])

        def _create_and_process(thread_id, agent_id, instructions):
            recorder.thread_ids_run.append(thread_id)
            return next(outcomes)

        recorder.runs.create_and_process = _create_and_process

        class _Client:
            def __init__(self, endpoint=None, credential=None):
                self.threads = recorder.threads
                self.messages = recorder.messages
                self.runs = recorder.runs

        saved, _log = _register_fake_azure_modules(_Client)
        try:
            monkeypatch.setattr(settings, "azure_foundry_endpoint", "https://f.example")
            monkeypatch.setattr(settings, "azure_foundry_agent_id", "agent-1")
            await fc._call_foundry_agent("prompt")
            fc._wait_for_cleanup(timeout=5)
        finally:
            _unregister_fake_azure_modules(saved)

        assert _fast_retries == [12.0]
        assert len(recorder.thread_ids_run) == 2
        assert len(set(recorder.thread_ids_run)) == 2  # thread nuovo


class TestConcurrencyCap:
    async def test_at_most_n_runs_together(self, monkeypatch):
        monkeypatch.setattr(settings, "foundry_max_concurrent", 2)
        fc._foundry_slots.clear()
        active = 0
        peak = 0
        release = asyncio.Event()

        async def _run(prompt):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await release.wait()
            active -= 1
            return "{}"

        monkeypatch.setattr(fc, "_run_foundry_in_thread", _run)
        tasks = [asyncio.ensure_future(fc._call_foundry_agent("p")) for _ in range(6)]
        # lascia girare i task (asyncio.wait non usa asyncio.sleep, che la
        # fixture sostituisce): solo 2 devono essere entrati nel run
        await asyncio.wait(tasks, timeout=0.1)
        assert active == 2
        assert peak == 2
        release.set()
        await asyncio.gather(*tasks)
        assert peak == 2
