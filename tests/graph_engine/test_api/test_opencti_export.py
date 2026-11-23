"""Esportazione su OpenCTI delle analisi malevole (pulsante dashboard)."""

from __future__ import annotations

import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from graph_engine.api import opencti_export as ox
from graph_engine.config import settings
from graph_engine.models import AnalysisTarget, Classification, TargetStatus, Verdict
from graph_engine.storage.repository import save_target


def _target(final_url=None):
    return AnalysisTarget(
        input_url="https://kit-123.pages.dev/login?x='1'",
        final_url=final_url,
        status=TargetStatus.done,
    )


class TestBuildIndicators:
    def test_urls_and_full_hostnames_without_duplicates(self):
        t = _target(final_url="https://kit-123.pages.dev/step2")
        inds = ox.build_indicators(t)
        assert [(i["type"], i["value"]) for i in inds] == [
            ("url", "https://kit-123.pages.dev/login?x='1'"),
            ("url", "https://kit-123.pages.dev/step2"),
            ("domain", "kit-123.pages.dev"),  # host completo, mai pages.dev
        ]

    def test_stix_pattern_escapes_quotes(self):
        url_ind = ox.build_indicators(_target())[0]
        assert url_ind["pattern"] == "[url:value = 'https://kit-123.pages.dev/login?x=\\'1\\'']"


class _FakeOpenCti:
    """OpenCTI simulato: risponde alle operazioni GraphQL per nome."""

    def __init__(self, fail_on: str | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.fail_on = fail_on
        self.counter = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer cti-key"
        body = json.loads(request.content)
        op = body["query"].split("(")[0].split()[-1]
        self.calls.append((op, body["variables"]))
        if op == self.fail_on:
            return httpx.Response(200, json={"errors": [{"message": "boom"}]})
        self.counter += 1
        new_id = f"id-{self.counter}"
        data = {
            "Markings": {"markingDefinitions": {"edges": [
                {"node": {"id": "marking-amber", "definition": "TLP:AMBER"}}]}},
            "Author": {"identityAdd": {"id": "author-1"}},
            "Label": {"labelAdd": {"id": f"label-{new_id}"}},
            "ExtRef": {"externalReferenceAdd": {"id": "ext-1"}},
            "Indicator": {"indicatorAdd": {"id": f"ind-{new_id}"}},
            "Obs": {"indicator": {"observables": {"edges": [{"node": {"id": f"obs-{new_id}"}}]}}},
            "Report": {"reportAdd": {"id": "report-1"}},
        }[op]
        return httpx.Response(200, json={"data": data})


@pytest.fixture
def cti_settings(monkeypatch):
    monkeypatch.setattr(settings, "opencti_url", "https://cti.example.org/")
    monkeypatch.setattr(settings, "opencti_api_key", "cti-key")
    monkeypatch.setattr(settings, "opencti_tlp", "TLP:AMBER")
    monkeypatch.setattr(settings, "opencti_author", "GraphEngine")
    monkeypatch.setattr(settings, "dashboard_public_url", "https://ge.example.org")


def _data():
    t = _target()
    v = Verdict(target_id=t.id, classification=Classification.phishing,
                confidence=0.92, produced_by="foundry", brand="Microsoft")
    return {"target": t, "verdict": v, "evidence": [], "states": [], "transitions": []}


_EXTERNAL = {"result": {"verdict": "malicious", "confidence": 0.92,
                        "signature": "Phishing: Microsoft Impersonation",
                        "recommended_action": "block", "reason": "Login Microsoft falso."}}


class TestExportAnalysis:
    async def test_creates_report_with_indicators(self, cti_settings):
        fake = _FakeOpenCti()
        out = await ox.export_analysis(_data(), _EXTERNAL,
                                       transport=httpx.MockTransport(fake.handler))

        ops = [op for op, _ in fake.calls]
        assert ops[:2] == ["Markings", "Author"]
        assert ops.count("Indicator") == 2  # URL + dominio
        report_vars = next(v for op, v in fake.calls if op == "Report")["input"]
        assert report_vars["name"] == "Phishing: Microsoft Impersonation – kit-123.pages.dev"
        assert report_vars["objectMarking"] == ["marking-amber"]
        assert report_vars["createdBy"] == "author-1"
        assert report_vars["confidence"] == 92
        assert report_vars["externalReferences"] == ["ext-1"]
        assert any(o.startswith("ind-") for o in report_vars["objects"])
        assert any(o.startswith("obs-") for o in report_vars["objects"])
        labels = [v["input"]["value"] for op, v in fake.calls if op == "Label"]
        assert labels == ["graphengine", "phishing", "microsoft"]
        ext = next(v for op, v in fake.calls if op == "ExtRef")["input"]
        assert ext["url"].startswith("https://ge.example.org/dashboard/#/analyses/")
        assert out["report_url"] == "https://cti.example.org/dashboard/analyses/reports/report-1"

    async def test_only_selected_indicators(self, cti_settings):
        fake = _FakeOpenCti()
        out = await ox.export_analysis(_data(), _EXTERNAL, selected_keys=["domain:kit-123.pages.dev"],
                                       transport=httpx.MockTransport(fake.handler))
        assert out["indicators"] == ["kit-123.pages.dev"]
        patterns = [v["input"]["pattern"] for op, v in fake.calls if op == "Indicator"]
        assert patterns == ["[domain-name:value = 'kit-123.pages.dev']"]

    async def test_graphql_error_raises(self, cti_settings):
        fake = _FakeOpenCti(fail_on="Report")
        with pytest.raises(ox.OpenCtiError, match="boom"):
            await ox.export_analysis(_data(), _EXTERNAL, transport=httpx.MockTransport(fake.handler))

    async def test_not_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "opencti_url", None)
        with pytest.raises(ox.OpenCtiNotConfigured):
            await ox.export_analysis(_data(), _EXTERNAL)


async def _save(db, classification):
    t = AnalysisTarget(input_url="https://kit-123.pages.dev/", status=TargetStatus.done)
    v = Verdict(target_id=t.id, classification=classification, confidence=0.9, produced_by="foundry")
    await save_target(t, [], [], [], v, db_path=db)
    return str(t.id)


class TestRoutes:
    async def test_status_and_export_then_no_duplicates(self, app, client, tmp_path, monkeypatch, cti_settings):
        db = str(tmp_path / "test.db")
        tid = await _save(db, Classification.phishing)
        calls = []

        async def _fake_export(data, external, selected_keys=None):
            calls.append(selected_keys)
            return {"report_id": "r1", "report_url": "https://cti/r1", "indicators": ["kit-123.pages.dev"]}

        monkeypatch.setattr("graph_engine.api.routes.export_analysis", _fake_export)

        status = (await client.get(f"/analyses/{tid}/opencti")).json()
        assert status["configured"] and status["eligible"] and status["exported"] is None
        assert [i["type"] for i in status["indicators"]] == ["url", "domain"]

        res = await client.post(f"/analyses/{tid}/opencti", json={"indicators": ["domain:kit-123.pages.dev"]})
        assert res.status_code == 200 and res.json()["report_id"] == "r1"
        assert calls == [["domain:kit-123.pages.dev"]]

        again = await client.post(f"/analyses/{tid}/opencti", json={})
        assert again.status_code == 409 and "https://cti/r1" in again.json()["detail"]
        status = (await client.get(f"/analyses/{tid}/opencti")).json()
        assert status["exported"]["report_url"] == "https://cti/r1"
        assert status["exported"]["exported_by"] == "admin"

    async def test_benign_analysis_not_exportable(self, app, client, tmp_path, cti_settings):
        tid = await _save(str(tmp_path / "test.db"), Classification.benign)
        res = await client.post(f"/analyses/{tid}/opencti", json={})
        assert res.status_code == 409

    async def test_not_configured_returns_503(self, app, client, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "opencti_url", None)
        tid = await _save(str(tmp_path / "test.db"), Classification.phishing)
        res = await client.post(f"/analyses/{tid}/opencti", json={})
        assert res.status_code == 503

    async def test_api_key_cannot_export(self, app, tmp_path, monkeypatch, cti_settings):
        monkeypatch.setattr(settings, "api_key", "k")
        tid = await _save(str(tmp_path / "test.db"), Classification.phishing)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t",
                               headers={"X-API-Key": "k"}) as c:
            res = await c.post(f"/analyses/{tid}/opencti", json={})
        assert res.status_code == 401
