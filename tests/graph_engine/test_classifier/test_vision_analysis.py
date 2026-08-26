"""Tests for vision_analysis — NEVER makes real Azure calls.

I confini esterni sono mockati dove il codice di produzione li tocca:

- **SDK moderna** (``azure.ai.vision.imageanalysis.aio``): i moduli
  ``azure.*`` NON sono installati nel venv di sviluppo — vengono
  iniettati in ``sys.modules`` sotto i NOMI VERI delle classi SDK
  (rete anti-self-fulfilling: se il codice importa il nome sbagliato,
  il test si rompe, come in test_foundry_classifier).
- **REST legacy** (``httpx.AsyncClient``): stub al confine httpx che
  registra URL/header/body di ogni ``post``.

Pattern di blocco rete (MISP/OpenCTI/URLhaus): quando
``settings.vision_configured`` è False, nessuna chiamata deve essere
tentata — gli stub esplodono se vengono toccati.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from graph_engine.config import settings
from graph_engine.classifier.vision_analysis import (
    analyze_screenshot,
    run_brand_detection,
    run_ocr,
)


# ---------------------------------------------------------------------------
# Helpers — configurazione
# ---------------------------------------------------------------------------


def _enable_vision(monkeypatch):
    """Forza la configurazione Vision sul singleton (come MISP/OpenCTI)."""
    monkeypatch.setattr(
        settings, "azure_vision_endpoint", "https://vision.example.com"
    )
    monkeypatch.setattr(settings, "azure_vision_key", "test-vision-key")


def _disable_vision(monkeypatch):
    """Forza la configurazione Vision a vuoto sul singleton."""
    monkeypatch.setattr(settings, "azure_vision_endpoint", None)
    monkeypatch.setattr(settings, "azure_vision_key", None)


# ---------------------------------------------------------------------------
# Fake SDK moderna — iniettata sotto i NOMI VERI delle classi
# ---------------------------------------------------------------------------


def _register_fake_vision_modules(fake_client_class, fake_visual_features):
    """Registra i moduli ``azure.*`` fake in ``sys.modules``.

    Iniettato sotto il nome REALE della classe SDK: se il codice di
    produzione importasse un nome sbagliato, l'import fallirebbe e il
    test si romperebbe rumorosamente.
    """
    saved = {}
    for name in (
        "azure",
        "azure.ai",
        "azure.ai.vision",
        "azure.ai.vision.imageanalysis",
        "azure.ai.vision.imageanalysis.aio",
        "azure.ai.vision.imageanalysis.models",
        "azure.core",
        "azure.core.credentials",
    ):
        saved[name] = sys.modules.get(name)
        mod = ModuleType(name)
        if name in (
            "azure",
            "azure.ai",
            "azure.ai.vision",
            "azure.ai.vision.imageanalysis",
            "azure.core",
        ):
            mod.__path__ = []
        sys.modules[name] = mod
    sys.modules["azure.ai.vision.imageanalysis.aio"].ImageAnalysisClient = (
        fake_client_class
    )
    sys.modules["azure.ai.vision.imageanalysis.models"].VisualFeatures = (
        fake_visual_features
    )
    sys.modules["azure.core.credentials"].AzureKeyCredential = lambda key: key
    return saved


def _unregister_fake_vision_modules(saved):
    """Ripristina ``sys.modules`` allo stato originale."""
    for name, original in saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


class _FakeVisualFeatures:
    """Mirror dell'enum ``VisualFeatures`` — il valore usato è READ."""

    READ = "READ"


class _FakeLine:
    def __init__(self, text: str):
        self.text = text


class _FakeBlock:
    def __init__(self, lines):
        self.lines = lines


class _FakeRead:
    """Mirror di ``ImageAnalysisResult.read``: blocks → lines → text."""

    blocks = [
        _FakeBlock(
            [
                _FakeLine("ATTENZIONE"),
                _FakeLine("Verifica il tuo account"),
            ]
        )
    ]


class _FakeImageAnalysisClient:
    """Stub per il confine SDK — registra i parametri della chiamata."""

    last_call: dict = {}

    def __init__(self, endpoint, credential):
        self._endpoint = endpoint
        self._credential = credential

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def analyze(self, image_data, visual_features):
        _FakeImageAnalysisClient.last_call = {
            "endpoint": self._endpoint,
            "credential": self._credential,
            "image_data": image_data,
            "visual_features": visual_features,
        }
        return SimpleNamespace(read=_FakeRead())


class _FakeImageAnalysisClientExploding(_FakeImageAnalysisClient):
    """Variante che fa esplodere ``analyze`` — per il percorso d'errore."""

    async def analyze(self, image_data, visual_features):
        raise RuntimeError("simulated Azure outage")


# ---------------------------------------------------------------------------
# Fake httpx — confine della REST legacy
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


class _FakeHttpxAsyncClient:
    """Stub per ``httpx.AsyncClient`` — registra ogni ``post``."""

    requests: list[dict] = []

    def __init__(self, timeout=None):
        self._timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, headers=None, content=None):
        _FakeHttpxAsyncClient.requests.append(
            {
                "url": url,
                "headers": dict(headers or {}),
                "content": content,
            }
        )
        return _FakeResponse(
            200,
            {
                "brands": [
                    {"name": "Microsoft", "confidence": 0.87},
                    # Entry malformata (senza name) → deve essere scartata
                    {"confidence": 0.5},
                ]
            },
        )


class _FakeHttpxAsyncClientExploding:
    """Client che esplode se ``post`` viene chiamato — per i test di
    blocco rete (se il codice tentasse la chiamata, il test fallisce)."""

    def __init__(self, timeout=None):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, *args, **kwargs):
        raise AssertionError("HTTP called while vision is disabled")


# ---------------------------------------------------------------------------
# run_ocr — SDK moderna
# ---------------------------------------------------------------------------


class TestRunOcr:
    """OCR via SDK moderna: VisualFeatures.READ, byte del file, mai eccezioni."""

    async def test_ocr_reads_file_bytes_and_uses_read_feature(
        self, monkeypatch, tmp_path
    ):
        """Il client riceve i byte del file e VisualFeatures.READ; il
        testo OCR è estratto da read.blocks[].lines[].text."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNG\r\n\x1a\nfake-image-bytes")
        _enable_vision(monkeypatch)

        saved = _register_fake_vision_modules(
            _FakeImageAnalysisClient, _FakeVisualFeatures
        )
        try:
            result = await run_ocr(str(png))
        finally:
            _unregister_fake_vision_modules(saved)

        assert result["error"] is None
        assert result["ocr_text"] == "ATTENZIONE\nVerifica il tuo account"

        call = _FakeImageAnalysisClient.last_call
        # Byte GREZZI del file locale — non un URL
        assert call["image_data"] == b"\x89PNG\r\n\x1a\nfake-image-bytes"
        # La feature richiesta è esattamente READ
        assert call["visual_features"] == [_FakeVisualFeatures.READ]
        # Endpoint e chiave arrivano dalla configurazione
        assert call["endpoint"] == "https://vision.example.com"
        assert call["credential"] == "test-vision-key"

    async def test_ocr_returns_error_when_sdk_raises(self, monkeypatch, tmp_path):
        """L'eccezione della SDK NON risale mai: error valorizzato."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")
        _enable_vision(monkeypatch)

        saved = _register_fake_vision_modules(
            _FakeImageAnalysisClientExploding, _FakeVisualFeatures
        )
        try:
            result = await run_ocr(str(png))
        finally:
            _unregister_fake_vision_modules(saved)

        assert result["ocr_text"] == ""
        assert result["error"] is not None
        assert "OCR failed" in result["error"]

    async def test_ocr_not_configured_returns_error_without_sdk_import(
        self, monkeypatch, tmp_path
    ):
        """Senza configurazione: return immediato — l'SDK non viene
        nemmeno importata (i moduli fake non sono registrati)."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")
        _disable_vision(monkeypatch)

        result = await run_ocr(str(png))
        assert result["ocr_text"] == ""
        assert result["error"] == "vision not configured"


# ---------------------------------------------------------------------------
# run_brand_detection — REST legacy v3.2
# ---------------------------------------------------------------------------


class TestRunBrandDetection:
    """Brand Detection via REST legacy: Ocp-Apim-Subscription-Key,
    octet-stream con byte grezzi, percorso /vision/v3.2/analyze."""

    async def test_brand_detection_legacy_rest_shape(self, monkeypatch, tmp_path):
        """La chiamata rispetta la forma v3.2 verificata sulla doc
        Microsoft: percorso, header a chiave e body binario."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNG\r\n\x1a\nfake-image-bytes")
        _enable_vision(monkeypatch)
        _FakeHttpxAsyncClient.requests.clear()

        with patch(
            "httpx.AsyncClient", _FakeHttpxAsyncClient
        ):
            result = await run_brand_detection(str(png))

        assert result["error"] is None
        # Entry senza "name" scartate, solo brand validi
        assert result["brands"] == [
            {"name": "Microsoft", "confidence": 0.87}
        ]

        assert len(_FakeHttpxAsyncClient.requests) == 1
        req = _FakeHttpxAsyncClient.requests[0]
        # Percorso esatto della REST legacy v3.2
        assert req["url"] == (
            "https://vision.example.com"
            "/vision/v3.2/analyze?visualFeatures=Brands"
        )
        # Autenticazione a CHIAVE della risorsa — NON Authorization Bearer
        assert (
            req["headers"]["Ocp-Apim-Subscription-Key"] == "test-vision-key"
        )
        assert "Authorization" not in req["headers"]
        # File binario locale: octet-stream con i byte grezzi nel body
        assert req["headers"]["Content-Type"] == "application/octet-stream"
        assert req["content"] == b"\x89PNG\r\n\x1a\nfake-image-bytes"

    async def test_brand_detection_http_error_returns_error(
        self, monkeypatch, tmp_path
    ):
        """Status != 200 → brands vuoti + error valorizzato, mai eccezioni."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")
        _enable_vision(monkeypatch)

        class _FakeClientError(_FakeHttpxAsyncClient):
            async def post(self, url, headers=None, content=None):
                return _FakeResponse(400, text="InvalidImageFormat")

        with patch("httpx.AsyncClient", _FakeClientError):
            result = await run_brand_detection(str(png))

        assert result["brands"] == []
        assert "Brand detection HTTP 400" in result["error"]

    async def test_brand_detection_not_configured_blocks_network(
        self, monkeypatch, tmp_path
    ):
        """Senza configurazione: nessuna chiamata HTTP — il client fake
        esploderebbe se il codice tentasse il post."""
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")
        _disable_vision(monkeypatch)

        with patch("httpx.AsyncClient", _FakeHttpxAsyncClientExploding):
            result = await run_brand_detection(str(png))

        assert result["brands"] == []
        assert result["error"] == "vision not configured"


# ---------------------------------------------------------------------------
# analyze_screenshot — orchestratore
# ---------------------------------------------------------------------------


class TestAnalyzeScreenshot:
    """Skip puliti senza rete; un fallimento non blocca l'altro."""

    async def test_not_configured_returns_skipped_without_calls(self, monkeypatch):
        """vision_configured False → skipped, NE run_ocr NE
        run_brand_detection vengono chiamate (pattern MISP/OpenCTI)."""
        _disable_vision(monkeypatch)

        with patch(
            "graph_engine.classifier.vision_analysis.run_ocr",
            new_callable=AsyncMock,
        ) as mock_ocr, patch(
            "graph_engine.classifier.vision_analysis.run_brand_detection",
            new_callable=AsyncMock,
        ) as mock_brands:
            result = await analyze_screenshot("/whatever.png")

        assert result == {
            "ocr_text": "",
            "brands": [],
            "skipped": "not configured",
        }
        mock_ocr.assert_not_awaited()
        mock_brands.assert_not_awaited()

    async def test_missing_file_returns_no_screenshot_without_calls(
        self, monkeypatch, tmp_path
    ):
        """Screenshot inesistente su disco → skip pulito, zero rete —
        anche con Vision configurata."""
        _enable_vision(monkeypatch)
        missing = str(tmp_path / "does-not-exist.png")

        with patch(
            "graph_engine.classifier.vision_analysis.run_ocr",
            new_callable=AsyncMock,
        ) as mock_ocr, patch(
            "graph_engine.classifier.vision_analysis.run_brand_detection",
            new_callable=AsyncMock,
        ) as mock_brands:
            result = await analyze_screenshot(missing)

        assert result == {
            "ocr_text": "",
            "brands": [],
            "skipped": "no screenshot",
        }
        mock_ocr.assert_not_awaited()
        mock_brands.assert_not_awaited()

    async def test_one_failure_does_not_block_the_other(
        self, monkeypatch, tmp_path
    ):
        """OCR fallisce (eccezione) ma i brand arrivano comunque — il
        fallimento di una chiamata non blocca l'altra."""
        _enable_vision(monkeypatch)
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")

        async def _ocr_explodes(image_path):
            raise RuntimeError("OCR blew up")

        async def _brands_ok(image_path):
            return {
                "brands": [{"name": "Poste Italiane", "confidence": 0.9}],
                "error": None,
            }

        with patch(
            "graph_engine.classifier.vision_analysis.run_ocr",
            new_callable=AsyncMock,
            side_effect=_ocr_explodes,
        ), patch(
            "graph_engine.classifier.vision_analysis.run_brand_detection",
            new_callable=AsyncMock,
            side_effect=_brands_ok,
        ):
            result = await analyze_screenshot(str(png))

        assert result["brands"] == [
            {"name": "Poste Italiane", "confidence": 0.9}
        ]
        assert result["ocr_text"] == ""
        assert any("OCR blew up" in e for e in result["errors"])

    async def test_both_results_merged_when_successful(
        self, monkeypatch, tmp_path
    ):
        """Entrambe le chiamate ok → ocr_text e brands riempiti."""
        _enable_vision(monkeypatch)
        png = tmp_path / "shot.png"
        png.write_bytes(b"\x89PNGfake")

        async def _ocr_ok(image_path):
            return {"ocr_text": "Pagina di login", "error": None}

        async def _brands_ok(image_path):
            return {
                "brands": [{"name": "Microsoft", "confidence": 0.8}],
                "error": None,
            }

        with patch(
            "graph_engine.classifier.vision_analysis.run_ocr",
            new_callable=AsyncMock,
            side_effect=_ocr_ok,
        ), patch(
            "graph_engine.classifier.vision_analysis.run_brand_detection",
            new_callable=AsyncMock,
            side_effect=_brands_ok,
        ):
            result = await analyze_screenshot(str(png))

        assert result["ocr_text"] == "Pagina di login"
        assert result["brands"] == [
            {"name": "Microsoft", "confidence": 0.8}
        ]
        assert "errors" not in result
