"""Arricchimento visivo del bundle L5 — Azure AI Vision.

Due capacità, due superfici API diverse della STESSA risorsa Azure
(``https://aigpt-pr-it-intelivx-resource.cognitiveservices.azure.com/``,
regione italynorth — riusata, nessuna risorsa nuova da creare):

- **OCR**: SDK moderna ``azure-ai-vision-imageanalysis`` con il client
  async nativo ``azure.ai.vision.imageanalysis.aio.ImageAnalysisClient``
  e ``VisualFeatures.READ``.  Serve per i casi in cui il DOM è vuoto o
  offuscato ma la pagina rende testo via canvas/immagini.

- **Brand Detection**: la SDK moderna (API v4) NON espone più i brand;
  l'unica superficie che li restituisce è la REST legacy v3.2
  ``POST {endpoint}/vision/v3.2/analyze?visualFeatures=Brands`` con
  autenticazione a CHIAVE della risorsa Cognitive Services (header
  ``Ocp-Apim-Subscription-Key`` — diversa dall'AAD usata per Foundry) e
  body ``application/octet-stream`` con i byte grezzi del file: gli
  screenshot sono PNG locali su disco, NON URL pubblici (quindi niente
  ``{"url": ...}`` nel body).

CONTRATTO: nessuna funzione di questo modulo lancia MAI eccezioni — ogni
funzione restituisce un dict con chiave ``"error"`` (None in caso di
successo).  Un fallimento di Vision non deve mai bloccare la
classificazione L5.
"""

from __future__ import annotations

import asyncio
import logging
import os

from graph_engine.config import settings

logger = logging.getLogger(__name__)

# Percorso della REST legacy v3.2 per la Brand Detection.
_BRAND_ANALYZE_PATH = "/vision/v3.2/analyze?visualFeatures=Brands"

# Limiti delle immagini accettate da Azure Vision: lato tra 50 e 16000
# px; file fino a 20 MB (Image Analysis 4.0, OCR) e 4 MB (REST v3.2,
# Brand Detection).  Fuori dai limiti la chiamata verrebbe rifiutata
# (InvalidImageSize): si salta e si annota il motivo.
_MIN_SIDE_PX = 50
_MAX_SIDE_PX = 16000
_MAX_OCR_BYTES = 20 * 1024 * 1024
_MAX_BRAND_BYTES = 4 * 1024 * 1024


def _png_dimensions(image_path: str) -> tuple[int, int] | None:
    """(larghezza, altezza) dall'header PNG, o None se non è un PNG."""
    try:
        with open(image_path, "rb") as fh:
            head = fh.read(24)
    except OSError:
        return None
    if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def _size_problem(image_path: str) -> str | None:
    """Motivo per cui l'immagine verrebbe rifiutata da Vision, o None."""
    dims = _png_dimensions(image_path)
    if dims is not None:
        width, height = dims
        if not (_MIN_SIDE_PX <= width <= _MAX_SIDE_PX
                and _MIN_SIDE_PX <= height <= _MAX_SIDE_PX):
            return f"image {width}x{height} outside Vision limits"
    try:
        if os.path.getsize(image_path) > _MAX_OCR_BYTES:
            return "image larger than 20 MB"
    except OSError:
        return None
    return None


async def run_ocr(image_path: str) -> dict:
    """OCR dello screenshot via SDK moderna ``ImageAnalysisClient``.

    Ritorna ``{"ocr_text": str, "error": None | str}`` — mai eccezioni.
    """
    if not settings.vision_configured:
        return {"ocr_text": "", "error": "vision not configured"}

    try:
        with open(image_path, "rb") as fh:
            image_data = fh.read()
    except OSError as exc:
        return {"ocr_text": "", "error": f"cannot read {image_path}: {exc}"}

    # Import dentro la funzione: il modulo resta importabile senza
    # l'SDK installata (vedi il pattern Foundry in foundry_classifier).
    try:
        from azure.ai.vision.imageanalysis.aio import ImageAnalysisClient
        from azure.ai.vision.imageanalysis.models import VisualFeatures
        from azure.core.credentials import AzureKeyCredential
    except ImportError as exc:
        return {
            "ocr_text": "",
            "error": (
                "azure-ai-vision-imageanalysis not installed; run: "
                f"pip install azure-ai-vision-imageanalysis ({exc})"
            ),
        }

    try:
        client = ImageAnalysisClient(
            endpoint=settings.azure_vision_endpoint,
            credential=AzureKeyCredential(settings.azure_vision_key),
        )
        async with client:
            result = await client.analyze(
                image_data=image_data,
                visual_features=[VisualFeatures.READ],
            )
        lines: list[str] = []
        if getattr(result, "read", None) is not None:
            for block in result.read.blocks:
                for line in block.lines:
                    lines.append(line.text)
        return {"ocr_text": "\n".join(lines), "error": None}
    except Exception as exc:
        logger.warning("Azure Vision OCR failed for %s: %s", image_path, exc)
        return {"ocr_text": "", "error": f"OCR failed: {exc}"}


async def run_brand_detection(image_path: str) -> dict:
    """Brand Detection via REST legacy v3.2 (httpx async).

    Ritorna ``{"brands": [{"name": ..., "confidence": ...}, ...],
    "error": None | str}`` — mai eccezioni.
    """
    if not settings.vision_configured:
        return {"brands": [], "error": "vision not configured"}

    try:
        with open(image_path, "rb") as fh:
            image_bytes = fh.read()
    except OSError as exc:
        return {"brands": [], "error": f"cannot read {image_path}: {exc}"}

    url = settings.azure_vision_endpoint.rstrip("/") + _BRAND_ANALYZE_PATH
    headers = {
        # Autenticazione a CHIAVE della risorsa Cognitive Services —
        # NON Authorization Bearer (che è l'autenticazione AAD usata
        # per Foundry, una risorsa/superficie diversa).
        "Ocp-Apim-Subscription-Key": settings.azure_vision_key,
        # File binario locale: i byte grezzi vanno nel body con
        # Content-Type application/octet-stream, NON come {"url": ...}.
        "Content-Type": "application/octet-stream",
    }

    try:
        import httpx
    except ImportError as exc:
        return {"brands": [], "error": f"httpx not installed: {exc}"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                headers=headers,
                content=image_bytes,
            )
        if response.status_code != 200:
            return {
                "brands": [],
                "error": (
                    f"Brand detection HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                ),
            }
        payload = response.json()
    except Exception as exc:
        logger.warning(
            "Azure Vision brand detection failed for %s: %s",
            image_path,
            exc,
        )
        return {"brands": [], "error": f"Brand detection failed: {exc}"}

    brands = [
        {"name": b.get("name", ""), "confidence": b.get("confidence", 0.0)}
        for b in payload.get("brands", [])
        if isinstance(b, dict) and b.get("name")
    ]
    return {"brands": brands, "error": None}


async def analyze_screenshot(image_path: str) -> dict:
    """Orchestratore: OCR + Brand Detection sullo stesso screenshot.

    - Vision non configurata → ``{"ocr_text": "", "brands": [],
      "skipped": "not configured"}`` SENZA tentare alcuna chiamata;
    - file inesistente su disco → ``{"ocr_text": "", "brands": [],
      "skipped": "no screenshot"}``, sempre senza rete;
    - altrimenti le due chiamate girano in parallelo
      (``asyncio.gather(..., return_exceptions=True)``): il fallimento
      di una NON blocca l'altra.

    Ritorna sempre ``{"ocr_text": str, "brands": [...], "errors": [...]}``
    (``"skipped"`` presente solo nei casi di skip, compresa un'immagine
    fuori dai limiti di Vision: lato fuori da 50–16000 px o file oltre
    20 MB; oltre 4 MB si salta solo la Brand Detection).
    """
    if not settings.vision_configured:
        return {"ocr_text": "", "brands": [], "skipped": "not configured"}
    if not os.path.isfile(image_path):
        return {"ocr_text": "", "brands": [], "skipped": "no screenshot"}
    problem = _size_problem(image_path)
    if problem is not None:
        # Nessuna chiamata destinata al rifiuto (InvalidImageSize).
        return {"ocr_text": "", "brands": [], "skipped": problem}

    async def _brands_if_small_enough() -> dict:
        try:
            too_big = os.path.getsize(image_path) > _MAX_BRAND_BYTES
        except OSError:
            too_big = False
        if too_big:
            return {"brands": [], "error": "brand detection skipped: image larger than 4 MB"}
        return await run_brand_detection(image_path)

    ocr_result, brand_result = await asyncio.gather(
        run_ocr(image_path),
        _brands_if_small_enough(),
        return_exceptions=True,
    )

    ocr_text = ""
    brands: list[dict] = []
    errors: list[str] = []
    for result in (ocr_result, brand_result):
        if isinstance(result, BaseException):
            errors.append(f"{type(result).__name__}: {result}")
            continue
        if not isinstance(result, dict):
            errors.append(f"unexpected result type: {type(result).__name__}")
            continue
        if "ocr_text" in result:
            ocr_text = result["ocr_text"] or ""
        if "brands" in result:
            brands = result["brands"] or []
        if result.get("error"):
            errors.append(result["error"])

    out: dict = {"ocr_text": ocr_text, "brands": brands}
    if errors:
        out["errors"] = errors
    return out
