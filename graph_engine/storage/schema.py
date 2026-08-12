"""SQL DDL for the append-only persistence layer.

Every analysis is a new row — same URL analysed twice produces
two independent ``analysis_target`` rows (different UUIDs), linked
by the same ``url_hash`` for historical grouping.

Schema mirrors :mod:`graph_engine.models` exactly.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Default database path — same ``data/`` directory used by OSINT cache and
# per-state artifacts
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = os.path.join("data", "graph_engine.db")

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

DDL = """
-- ============================================================================
-- AnalysisTarget — one row per exploration run (append-only)
-- ============================================================================

CREATE TABLE IF NOT EXISTS analysis_target (
    id              TEXT PRIMARY KEY,          -- UUID
    input_url       TEXT    NOT NULL,
    canonical_url   TEXT,                      -- NULLable
    url_hash        TEXT,                      -- NULLable; indexed, NOT unique
    final_url       TEXT,                      -- NULLable
    status          TEXT    NOT NULL DEFAULT 'queued',  -- TargetStatus enum
    root_state_id   TEXT,                      -- UUID → State.id  (NULLable)
    created_at      TEXT    NOT NULL           -- ISO-8601 datetime
);

CREATE INDEX IF NOT EXISTS idx_target_url_hash
    ON analysis_target(url_hash);

-- ============================================================================
-- State — graph node, dedup on (target_id, url, dom_hash) in-memory
-- ============================================================================

CREATE TABLE IF NOT EXISTS state (
    id              TEXT PRIMARY KEY,          -- UUID
    target_id       TEXT    NOT NULL REFERENCES analysis_target(id)
                            ON DELETE CASCADE,
    url             TEXT    NOT NULL,
    dom_hash        TEXT    NOT NULL,
    depth           INTEGER NOT NULL DEFAULT 0,
    screenshot_ref  TEXT,
    har_ref         TEXT
);

CREATE INDEX IF NOT EXISTS idx_state_target
    ON state(target_id);

-- ============================================================================
-- Transition — typed arc between two States
-- ============================================================================

CREATE TABLE IF NOT EXISTS transition (
    id              TEXT PRIMARY KEY,          -- UUID
    target_id       TEXT    NOT NULL REFERENCES analysis_target(id)
                            ON DELETE CASCADE,
    from_state      TEXT    NOT NULL,
    to_state        TEXT    NOT NULL,
    kind            TEXT    NOT NULL,          -- TransitionKind enum
    trigger         TEXT,                      -- JSON dict, NULLable
    ts              TEXT    NOT NULL           -- ISO-8601 datetime
);

CREATE INDEX IF NOT EXISTS idx_transition_target
    ON transition(target_id);

-- ============================================================================
-- Evidence — atomic signal with full provenance
-- ============================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,          -- UUID
    target_id       TEXT    NOT NULL REFERENCES analysis_target(id)
                            ON DELETE CASCADE,
    scope           TEXT    NOT NULL,          -- EvidenceScope enum
    scope_id        TEXT    NOT NULL,          -- UUID
    layer           TEXT    NOT NULL,          -- L0 .. L5
    key             TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    weight          REAL    NOT NULL DEFAULT 1.0,
    produced_by     TEXT    NOT NULL,
    ts              TEXT    NOT NULL           -- ISO-8601 datetime
);

CREATE INDEX IF NOT EXISTS idx_evidence_target
    ON evidence(target_id);

-- ============================================================================
-- Verdict — 1:1 with analysis_target  (uses target_id as PK)
-- ============================================================================

CREATE TABLE IF NOT EXISTS verdict (
    target_id       TEXT PRIMARY KEY REFERENCES analysis_target(id)
                            ON DELETE CASCADE,
    classification  TEXT    NOT NULL,          -- Classification enum
    confidence      REAL    NOT NULL DEFAULT 0.0,
    produced_by     TEXT    NOT NULL DEFAULT 'foundry',
    brand           TEXT,
    kit_family      TEXT,
    rationale       TEXT,
    final_url       TEXT,
    exfil_endpoint  TEXT
);

-- ============================================================================
-- PRAGMA — enforce foreign keys  (SQLite requires per-connection PRAGMA)
-- ============================================================================
-- Called explicitly in repository.connect() — cannot be in DDL.
"""

# ---------------------------------------------------------------------------
# Helper — ensure the data directory exists
# ---------------------------------------------------------------------------


def ensure_data_dir(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create the parent directory of *db_path* if it does not exist."""
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
