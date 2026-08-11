"""L0 ingestion pipeline — refang → unwrap → extract → canonicalize.

The single entry point ``ingest()`` takes a raw URL (possibly defanged,
wrapped, or containing nested payloads) and returns a normalised dict
ready to populate an ``AnalysisTarget`` and its L0 ``Evidence`` records.
"""

from __future__ import annotations

from graph_engine.ingestion.refang import refang
from graph_engine.ingestion.unwrap import unwrap_url, UnwrapResult, UnwrapStep
from graph_engine.ingestion.payload_extraction import extract_nested_payloads
from graph_engine.ingestion.canonicalize import canonicalize_and_hash


def ingest(raw_url: str) -> dict:
    """Run the full L0 pipeline on *raw_url*.

    Returns a dict::

        {
            "input_url": str,           # original raw URL (preserved verbatim)
            "canonical_url": str,       # normalised URL after L0 processing
            "url_hash": str,            # SHA-256 of canonical_url
            "unwrap_chain": [...],      # list of serialised UnwrapStep dicts
            "nested_payloads": [...],   # list of payload dicts from extraction
        }
    """
    # 1. Refang
    clean = refang(raw_url)

    # 2. Unwrap
    result: UnwrapResult = unwrap_url(clean)

    # 3. Extract nested payloads (from the final inner URL)
    payloads = extract_nested_payloads(result.final_url)

    # 4. Canonicalize
    canonical_url, url_hash = canonicalize_and_hash(result.final_url)

    return {
        "input_url": raw_url,
        "canonical_url": canonical_url,
        "url_hash": url_hash,
        "unwrap_chain": [
            {
                "wrapper_type": step.wrapper_type,
                "input_url": step.input_url,
                "output_url": step.output_url,
                "opaque": step.opaque,
            }
            for step in result.chain
        ],
        "nested_payloads": payloads,
    }
