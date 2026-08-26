"""Runner riusabile della pipeline L0→L5 con lifecycle status su SQLite.

Usabile in tre modi:

1. **Standalone** (es. wrapper Trellix):
   ``target_id = await run_full_analysis("https://example.com")``

2. **Con target pre-creato** (usato dalla route POST /analyses per eliminare
   la race 202→GET 404):
   ``target = AnalysisTarget(input_url=url); await save_target(target, ...); task = asyncio.create_task(run_full_analysis(url, target=target))``

3. **Con budget personalizzato**:
   ``target_id = await run_full_analysis(url, budget=Budget(max_depth=3))``

Lifecycle status: **queued** → **running** → **done** | **error**

Il browser Playwright rimane aperto **solo** durante L4 (StateGraphExplorer).
L5 (classificazione) gira dopo che il browser è stato chiuso — il
classificatore legge DOM snapshot da disco e strutture in memoria.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright

from graph_engine.budget import Budget
from graph_engine.models import (
    AnalysisTarget,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    Verdict,
)
from graph_engine.storage.repository import get_target_by_id, save_target
from graph_engine.storage.schema import DEFAULT_DB_PATH

logger = logging.getLogger("graph_engine.api")

DEFAULT_ARTIFACT_ROOT = Path("data") / "graph_artifacts"


# ---------------------------------------------------------------------------
# Classificazione L5 — estratta da cli.py per riuso
# ---------------------------------------------------------------------------


def _extract_visible_text(html: str) -> str:
    """Strip scripts, styles, tags, and extra whitespace; truncate to ~1500 chars."""
    text = re.sub(
        r"<(script|style|noscript)\b[^>]*>.*?</\1>",
        "",
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#x27;", "'").replace("&nbsp;", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:1500]


async def _run_classification(
    target: AnalysisTarget,
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
    lexical_risk_score: Optional[float] = None,
    passive_risk_score: Optional[float] = None,
) -> Optional[Verdict]:
    """Build evidence bundle, run prefilter + classifier, return Verdict.

    Estratta da ``cli.py:_run_classification`` per essere riusabile sia
    dalla CLI che dall'API.
    """
    from graph_engine.classifier.evidence_bundle import build_evidence_bundle
    from graph_engine.classifier.prefilter import prefilter

    # Leaf detection: stati senza transizioni OUTbound
    from_state_ids = {str(t.from_state) for t in transitions}
    leaf_states = [s for s in states if str(s.id) not in from_state_ids]

    # Raccogli testo visibile, titoli, form fields dai leaf states
    leaf_form_fields: dict[str, list[dict]] = {}
    leaf_visible_text: dict[str, str] = {}
    leaf_titles: dict[str, str] = {}

    for s in leaf_states:
        sid = str(s.id)
        leaf_form_fields[sid] = []
        leaf_visible_text[sid] = ""
        leaf_titles[sid] = ""

        if s.har_ref:
            dom_path = os.path.join(os.path.dirname(s.har_ref), "dom.html")
            if os.path.isfile(dom_path):
                try:
                    with open(dom_path, encoding="utf-8") as fh:
                        html = fh.read()
                except Exception:
                    html = ""
                if html:
                    title_match = re.search(
                        r"<title[^>]*>(.*?)</title>",
                        html,
                        re.DOTALL | re.IGNORECASE,
                    )
                    if title_match:
                        leaf_titles[sid] = title_match.group(1).strip()
                    leaf_visible_text[sid] = _extract_visible_text(html)

    # Bundle
    bundle = await build_evidence_bundle(
        target_url=target.input_url,
        canonical_url=target.final_url,
        states=states,
        transitions=transitions,
        evidence=evidence,
        leaf_form_fields=leaf_form_fields,
        leaf_visible_text=leaf_visible_text,
        leaf_titles=leaf_titles,
        lexical_risk_score=lexical_risk_score,
        passive_risk_score=passive_risk_score,
    )
    bundle["target_id"] = str(target.id)

    # Prefilter → classifier
    verdict = prefilter(bundle)
    if verdict is not None:
        return verdict

    from graph_engine.classifier.foundry_classifier import classify

    # Nota: il contenuto visivo raggiunge il modello come TESTO nel
    # bundle (OCR + Brand Detection via Azure AI Vision) — nessuno
    # screenshot viene allegato alla chiamata Foundry.
    return await classify(bundle)


# ---------------------------------------------------------------------------
# Public API — il runner principale
# ---------------------------------------------------------------------------


async def run_full_analysis(
    raw_url: str,
    budget: Optional[Budget] = None,
    classify: bool = True,
    target: Optional[AnalysisTarget] = None,
    db_path: str = DEFAULT_DB_PATH,
    top_n_actions: int = 3,
    capture_artifacts: bool = True,
    captcha_wait_s: int = 8,
    l2_timeout_s: Optional[float] = None,
    l3_timeout_s: Optional[float] = None,
) -> str:
    """Esegue la pipeline completa L0→L5 e persiste tutto su SQLite.

    Args:
        raw_url: URL grezzo (può essere defanged — ``hxxp://...``).
        budget: Parametri di budget per l'esplorazione. Se ``None``, usa
                i default di ``Budget()``.
        classify: Se ``True``, esegue la classificazione L5 dopo
                  l'esplorazione.
        target: Se fornito, è il target **già salvato** come ``queued``
                dalla route POST.  ``run_full_analysis`` lo aggiorna
                a ``running`` e poi a ``done``/``error``.  Se ``None``,
                la funzione crea e salva un nuovo target internamente.
        db_path: Percorso del database SQLite.
        top_n_actions: Massimo candidati click per stato.
        capture_artifacts: Se ``True``, salva screenshot, DOM, HAR per
                           ogni stato.
        captcha_wait_s: Secondi di attesa per auto-risoluzione CAPTCHA
                        (default: 8s; fast path Trellix: 4s).
        l2_timeout_s: Timeout in secondi per le query OSINT L2
                      (crt.sh, RDAP, DNS).  Se ``None``, ogni provider
                      usa il proprio default.
        l3_timeout_s: Timeout in secondi per JARM (L3).  Se ``None``,
                      usa il default (10s).  Le altre sonde L3
                      mantengono i propri timeout interni.

    Returns:
        ``str(target.id)`` — l'UUID dell'analisi persistita.

    Raises:
        Rilancia qualsiasi eccezione dopo aver segnato il target come
        ``error`` su SQLite.
    """
    # ── Setup target ──────────────────────────────────────────────────────
    analysis_target = target or AnalysisTarget(input_url=raw_url)

    if target is None:
        # Standalone: crea e salva "queued" prima di qualunque analisi
        await save_target(analysis_target, [], [], [], None, db_path=db_path)

    # Aggiorna a "running"
    analysis_target.status = TargetStatus.running
    await save_target(analysis_target, [], [], [], None, db_path=db_path)

    states: list[State] = []
    transitions: list[Transition] = []
    evidence: list[Evidence] = []
    verdict: Optional[Verdict] = None
    explorer = None  # inizializzato prima del try per il controllo nell'except

    try:
        # ── L0 ingestion (sync, puro — refang/unwrap/canonicalize) ────────
        from graph_engine.ingestion.pipeline import ingest

        ingested = ingest(raw_url)

        # ── L1 lexical (sync) ──────────────────────────────────────────────
        from graph_engine.lexical.analyzer import analyze as l1_analyze

        l1_result = l1_analyze(
            ingested["canonical_url"],
            ingested["nested_payloads"],
        )

        # ── L2 passive OSINT ∥ L3 active low-interaction (async, rete) ───
        # Nessuno scambio dati tra i due strati → corrono in PARALLELO
        # (gather, non sequenziali): nel fast path Trellix il tempo
        # L2+L3 si dimezza (entrambi cappati a FAST_*_TIMEOUT_S).
        from graph_engine.osint.analyzer import analyze as l2_analyze
        from graph_engine.active.analyzer import analyze as l3_analyze

        l2_result, l3_result = await asyncio.gather(
            l2_analyze(ingested["canonical_url"], timeout_s=l2_timeout_s),
            l3_analyze(ingested["canonical_url"], timeout_s=l3_timeout_s),
        )

        budget_obj = budget or Budget()

        # ── L4 browser Playwright — SOLO qui ───────────────────────────────
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                from graph_engine.explorer import StateGraphExplorer

                explorer = StateGraphExplorer(browser)
                explored = await explorer.run(
                    ingested["canonical_url"],
                    budget=budget_obj,
                    capture_artifacts=capture_artifacts,
                    top_n_actions=top_n_actions,
                    captcha_wait_s=captcha_wait_s,
                    profile=l3_result["recommended_profile"],
                    target_id=analysis_target.id,
                    cloaking_profile=l3_result.get("cloaking_profile"),
                )
            finally:
                await browser.close()

        states = explorer.states
        transitions = explorer.transitions
        evidence = explorer.evidence

        # ── Patch L0 fields sull'AnalysisTarget ─────────────────────────
        analysis_target.input_url = ingested["input_url"]
        analysis_target.canonical_url = ingested["canonical_url"]
        analysis_target.url_hash = ingested["url_hash"]
        analysis_target.final_url = explored.final_url
        analysis_target.root_state_id = explored.root_state_id

        tid = analysis_target.id

        # ── Register L0 Evidence ───────────────────────────────────────────
        for i, step in enumerate(ingested["unwrap_chain"]):
            evidence.append(
                Evidence(
                    target_id=tid,
                    scope=EvidenceScope.target,
                    scope_id=tid,
                    layer="L0",
                    key=f"unwrap_step_{i}",
                    value=(
                        f"{step['wrapper_type']}: "
                        f"{step['input_url']} → {step['output_url']}"
                        f"{' [opaque]' if step.get('opaque') else ''}"
                    ),
                    produced_by="ingestion.unwrap",
                )
            )
        for payload in ingested["nested_payloads"]:
            evidence.append(
                Evidence(
                    target_id=tid,
                    scope=EvidenceScope.target,
                    scope_id=tid,
                    layer="L0",
                    key=f"nested_payload_{payload['kind']}",
                    value=payload["decoded"],
                    produced_by="ingestion.payload_extraction",
                )
            )

        # ── Register L1/L2/L3 Evidence ────────────────────────────────────
        for ev in (
            l1_result["evidence"] + l2_result["evidence"] + l3_result["evidence"]
        ):
            evidence.append(
                Evidence(
                    target_id=tid,
                    scope=EvidenceScope.target,
                    scope_id=tid,
                    layer=ev["layer"],
                    key=ev["key"],
                    value=ev["value"] if isinstance(ev["value"], str) else json.dumps(ev["value"]),
                    weight=ev.get("weight", 1.0),
                    produced_by=ev["produced_by"],
                )
            )

        # ── L5 classification (DOPO la chiusura del browser) ──────────────
        if classify:
            verdict = await _run_classification(
                analysis_target, states, transitions, evidence,
                lexical_risk_score=l1_result["lexical_risk_score"],
                passive_risk_score=l2_result["passive_risk_score"],
            )

        # ── Final save ────────────────────────────────────────────────────
        analysis_target.status = TargetStatus.done
        await save_target(
            analysis_target, states, transitions, evidence, verdict,
            db_path=db_path,
        )

        logger.info("Analysis %s completed — %d states, %d transitions",
                     tid, len(states), len(transitions))
        return str(tid)

    except Exception as exc:
        logger.exception("Pipeline failed for %s", analysis_target.id)

        # Ora che target_id viene iniettato in explorer.run(), tutti i
        # record figli (states, transitions, evidence) nascono già con
        # l'UUID API corretto.  Possiamo quindi salvare TUTTO ciò che
        # l'esploratore è riuscito a produrre prima del fallimento.
        #
        # Se il fallimento avviene PRIMA che l'esploratore esista
        # (es. errore in L0/L1/L2/L3), usiamo liste vuote come fallback.

        error_evidence = Evidence(
            target_id=analysis_target.id,
            scope=EvidenceScope.target,
            scope_id=analysis_target.id,
            layer="API",
            key="pipeline_error",
            value=f"{type(exc).__name__}: {exc}",
            produced_by="api.pipeline_runner",
        )

        partial_states: list[State] = []
        partial_transitions: list[Transition] = []
        partial_evidence: list[Evidence] = []

        # Se l'esploratore esiste (l'errore è avvenuto durante o dopo L4),
        # salviamo tutto ciò che è riuscito a produrre.  Se l'errore è
        # avvenuto prima (L0/L1/L2/L3), salviamo liste vuote.
        if explorer is not None:
            partial_states = explorer.states
            partial_transitions = explorer.transitions
            partial_evidence = list(explorer.evidence)

        # La pipeline_error va SEMPRE in coda, dopo le evidenze parziali
        partial_evidence.append(error_evidence)

        try:
            analysis_target.status = TargetStatus.error
            await save_target(
                analysis_target,
                partial_states,
                partial_transitions,
                partial_evidence,
                None,
                db_path=db_path,
            )
        except Exception:
            logger.exception(
                "Failed to persist error status for %s", analysis_target.id,
            )
        raise
