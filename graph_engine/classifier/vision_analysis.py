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
    (``"skipped"`` presente solo nei due casi di skip).
    """
    if not settings.vision_configured:
        return {"ocr_text": "", "brands": [], "skipped": "not configured"}
    if not os.path.isfile(image_path):
        return {"ocr_text": "", "brands": [], "skipped": "no screenshot"}

    ocr_result, brand_result = await asyncio.gather(
        run_ocr(image_path),
        run_brand_detection(image_path),
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
