"""Async repository — save and load full analysis graphs via aiosqlite.

Every ``save_target()`` call is a single transaction.  The operation is
**idempotent** on the target UUID: ``INSERT OR REPLACE`` ensures that
re-saving the same target object does not create duplicate rows.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from graph_engine.models import (
    AnalysisTarget,
    Classification,
    Evidence,
    EvidenceScope,
    State,
    TargetStatus,
    Transition,
    TransitionKind,
    Verdict,
)
from graph_engine.storage.schema import DDL, DEFAULT_DB_PATH, ensure_data_dir

# ---------------------------------------------------------------------------
# Helpers — model ↔ SQL row
# ---------------------------------------------------------------------------


def _uuid_str(val) -> str:
    return str(val)


def _dt_str(val: datetime) -> str:
    """ISO-8601 UTC with Z suffix — round-trippable."""
    if val.tzinfo is None:
        val = val.replace(tzinfo=timezone.utc)
    return val.isoformat()


def _dt_from_str(val: str) -> datetime:
    dt = datetime.fromisoformat(val)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _opt_dt_from_str(val: str | None) -> datetime | None:
    if val is None:
        return None
    return _dt_from_str(val)


def _target_row(target: AnalysisTarget) -> dict:
    return {
        "id": _uuid_str(target.id),
        "input_url": target.input_url,
        "canonical_url": target.canonical_url,
        "url_hash": target.url_hash,
        "final_url": target.final_url,
        "status": target.status.value,
        "root_state_id": _uuid_str(target.root_state_id) if target.root_state_id else None,
        "created_at": _dt_str(target.created_at),
    }


def _state_row(state: State) -> dict:
    return {
        "id": _uuid_str(state.id),
        "target_id": _uuid_str(state.target_id),
        "url": state.url,
        "dom_hash": state.dom_hash,
        "depth": state.depth,
        "screenshot_ref": state.screenshot_ref,
        "har_ref": state.har_ref,
    }


def _transition_row(t: Transition) -> dict:
    return {
        "id": _uuid_str(t.id),
        "target_id": _uuid_str(t.target_id),
        "from_state": _uuid_str(t.from_state),
        "to_state": _uuid_str(t.to_state),
        "kind": t.kind.value,
        "trigger": json.dumps(t.trigger) if t.trigger else None,
        "ts": _dt_str(t.ts),
    }


def _evidence_row(e: Evidence) -> dict:
    return {
        "id": _uuid_str(e.id),
        "target_id": _uuid_str(e.target_id),
        "scope": e.scope.value,
        "scope_id": _uuid_str(e.scope_id),
        "layer": e.layer,
        "key": e.key,
        "value": e.value,
        "weight": e.weight,
        "produced_by": e.produced_by,
        "ts": _dt_str(e.ts),
    }


def _verdict_row(v: Verdict) -> dict:
    return {
        "target_id": _uuid_str(v.target_id),
        "classification": v.classification.value,
        "confidence": v.confidence,
        "produced_by": v.produced_by,
        "brand": v.brand,
        "kit_family": v.kit_family,
        "rationale": v.rationale,
        "final_url": v.final_url,
        "exfil_endpoint": v.exfil_endpoint,
    }


# ---------------------------------------------------------------------------
# Row → model deserialisation
# ---------------------------------------------------------------------------


def _target_from_row(row: dict) -> AnalysisTarget:
    return AnalysisTarget(
        id=row["id"],
        input_url=row["input_url"],
        canonical_url=row["canonical_url"],
        url_hash=row["url_hash"],
        final_url=row["final_url"],
        status=TargetStatus(row["status"]),
        root_state_id=row["root_state_id"],
        created_at=_dt_from_str(row["created_at"]),
    )


def _state_from_row(row: dict) -> State:
    return State(
        id=row["id"],
        target_id=row["target_id"],
        url=row["url"],
        dom_hash=row["dom_hash"],
        depth=row["depth"],
        screenshot_ref=row["screenshot_ref"],
        har_ref=row["har_ref"],
    )


def _transition_from_row(row: dict) -> Transition:
    trigger = row.get("trigger")
    return Transition(
        id=row["id"],
        target_id=row["target_id"],
        from_state=row["from_state"],
        to_state=row["to_state"],
        kind=TransitionKind(row["kind"]),
        trigger=json.loads(trigger) if trigger else None,
        ts=_dt_from_str(row["ts"]),
    )


def _evidence_from_row(row: dict) -> Evidence:
    return Evidence(
        id=row["id"],
        target_id=row["target_id"],
        scope=EvidenceScope(row["scope"]),
        scope_id=row["scope_id"],
        layer=row["layer"],
        key=row["key"],
        value=row["value"],
        weight=row["weight"],
        produced_by=row["produced_by"],
        ts=_dt_from_str(row["ts"]),
    )


def _verdict_from_row(row: dict) -> Verdict:
    return Verdict(
        target_id=row["target_id"],
        classification=Classification(row["classification"]),
        confidence=row["confidence"],
        produced_by=row["produced_by"],
        brand=row["brand"],
        kit_family=row["kit_family"],
        rationale=row["rationale"],
        final_url=row["final_url"],
        exfil_endpoint=row["exfil_endpoint"],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def save_target(
    target: AnalysisTarget,
    states: list[State],
    transitions: list[Transition],
    evidence: list[Evidence],
    verdict: Verdict | None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Persist an entire analysis graph inside a single transaction.

    **Idempotent** on *target.id* — calling twice with the same target
    UUID replaces rows via ``INSERT OR REPLACE``, it does not duplicate.
    """
    ensure_data_dir(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)

        await conn.execute("BEGIN")
        try:
            await conn.execute(
                """INSERT OR REPLACE INTO analysis_target
                   (id, input_url, canonical_url, url_hash, final_url,
                    status, root_state_id, created_at)
                   VALUES (:id, :input_url, :canonical_url, :url_hash, :final_url,
                           :status, :root_state_id, :created_at)""",
                _target_row(target),
            )

            for s in states:
                await conn.execute(
                    """INSERT OR REPLACE INTO state
                       (id, target_id, url, dom_hash, depth,
                        screenshot_ref, har_ref)
                       VALUES (:id, :target_id, :url, :dom_hash, :depth,
                               :screenshot_ref, :har_ref)""",
                    _state_row(s),
                )

            for t in transitions:
                await conn.execute(
                    """INSERT OR REPLACE INTO transition
                       (id, target_id, from_state, to_state, kind, trigger, ts)
                       VALUES (:id, :target_id, :from_state, :to_state,
                               :kind, :trigger, :ts)""",
                    _transition_row(t),
                )

            for e in evidence:
                await conn.execute(
                    """INSERT OR REPLACE INTO evidence
                       (id, target_id, scope, scope_id, layer, key, value,
                        weight, produced_by, ts)
                       VALUES (:id, :target_id, :scope, :scope_id, :layer,
                               :key, :value, :weight, :produced_by, :ts)""",
                    _evidence_row(e),
                )

            if verdict is not None:
                await conn.execute(
                    """INSERT OR REPLACE INTO verdict
                       (target_id, classification, confidence, produced_by,
                        brand, kit_family, rationale, final_url, exfil_endpoint)
                       VALUES (:target_id, :classification, :confidence,
                               :produced_by, :brand, :kit_family, :rationale,
                               :final_url, :exfil_endpoint)""",
                    _verdict_row(verdict),
                )

            await conn.commit()
        except Exception:
            await conn.rollback()
            raise


async def get_target_by_id(
    target_id: str,
    db_path: str = DEFAULT_DB_PATH,
) -> dict | None:
    """Return the complete analysis graph for *target_id*, or ``None``.

    The returned dict has keys ``target``, ``states``, ``transitions``,
    ``evidence``, ``verdict`` — verdict is ``None`` if not present.
    """
    ensure_data_dir(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)
        conn.row_factory = aiosqlite.Row

        # Target
        async with conn.execute(
            "SELECT * FROM analysis_target WHERE id = ?", (target_id,)
        ) as cur:
            target_row = await cur.fetchone()

        if target_row is None:
            return None

        target = _target_from_row(dict(target_row))

        # States
        states: list[State] = []
        async with conn.execute(
            "SELECT * FROM state WHERE target_id = ? ORDER BY depth, id", (target_id,)
        ) as cur:
            async for row in cur:
                states.append(_state_from_row(dict(row)))

        # Transitions
        transitions: list[Transition] = []
        async with conn.execute(
            "SELECT * FROM transition WHERE target_id = ? ORDER BY ts", (target_id,)
        ) as cur:
            async for row in cur:
                transitions.append(_transition_from_row(dict(row)))

        # Evidence
        evidence: list[Evidence] = []
        async with conn.execute(
            "SELECT * FROM evidence WHERE target_id = ? ORDER BY ts", (target_id,)
        ) as cur:
            async for row in cur:
                evidence.append(_evidence_from_row(dict(row)))

        # Verdict
        verdict: Verdict | None = None
        async with conn.execute(
            "SELECT * FROM verdict WHERE target_id = ?", (target_id,)
        ) as cur:
            v_row = await cur.fetchone()
            if v_row is not None:
                verdict = _verdict_from_row(dict(v_row))

    return {
        "target": target,
        "states": states,
        "transitions": transitions,
        "evidence": evidence,
        "verdict": verdict,
    }


async def get_history_for_url_hash(
    url_hash: str,
    db_path: str = DEFAULT_DB_PATH,
) -> list[dict]:
    """All historical analyses for *url_hash*, newest first.

    Each entry is a compact summary — not the full graph.
    """
    ensure_data_dir(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)
        conn.row_factory = aiosqlite.Row

        async with conn.execute(
            """SELECT at.id, at.input_url, at.final_url, at.status,
                      at.created_at,
                      v.classification, v.confidence, v.brand, v.kit_family,
                      v.rationale,
                      (SELECT COUNT(*) FROM state WHERE target_id = at.id) AS num_states,
                      (SELECT COUNT(*) FROM transition WHERE target_id = at.id) AS num_transitions
               FROM analysis_target at
               LEFT JOIN verdict v ON v.target_id = at.id
               WHERE at.url_hash = ?
               ORDER BY at.created_at DESC""",
            (url_hash,),
        ) as cur:
            rows = await cur.fetchall()

    return [dict(r) for r in rows]


async def list_targets(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    classification: str | None = None,
    search: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> list[dict]:
    """Elenca le sottomissioni (analysis_target), più recenti prima.

    Pensata per la dashboard: ogni riga è un summary compatto (stesso
    formato di :func:`get_history_for_url_hash`, ma su TUTTE le
    sottomissioni invece che su un singolo ``url_hash``). Filtri opzionali
    e combinabili:

    - ``status``: match esatto su ``analysis_target.status``.
    - ``classification``: match esatto sul ``verdict.classification``.
    - ``search``: sottostringa case-insensitive su ``input_url`` o
      ``final_url``.
    """
    ensure_data_dir(db_path)

    clauses: list[str] = []
    params: list = []
    if status is not None:
        clauses.append("at.status = ?")
        params.append(status)
    if classification is not None:
        clauses.append("v.classification = ?")
        params.append(classification)
    if search is not None:
        clauses.append("(at.input_url LIKE ? OR at.final_url LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)
        conn.row_factory = aiosqlite.Row

        async with conn.execute(
            f"""SELECT at.id, at.input_url, at.final_url, at.status,
                       at.created_at,
                       v.classification, v.confidence, v.brand, v.kit_family,
                       v.rationale,
                       (SELECT COUNT(*) FROM state WHERE target_id = at.id) AS num_states,
                       (SELECT COUNT(*) FROM transition WHERE target_id = at.id) AS num_transitions
                FROM analysis_target at
                LEFT JOIN verdict v ON v.target_id = at.id
                {where}
                ORDER BY at.created_at DESC
                LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ) as cur:
            rows = await cur.fetchall()

    return [dict(r) for r in rows]


async def count_targets(
    status: str | None = None,
    classification: str | None = None,
    search: str | None = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Conta le sottomissioni che soddisfano gli stessi filtri di :func:`list_targets`.

    Usato dalla dashboard per la paginazione (``total``).
    """
    ensure_data_dir(db_path)

    clauses: list[str] = []
    params: list = []
    if status is not None:
        clauses.append("at.status = ?")
        params.append(status)
    if classification is not None:
        clauses.append("v.classification = ?")
        params.append(classification)
    if search is not None:
        clauses.append("(at.input_url LIKE ? OR at.final_url LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)

        async with conn.execute(
            f"""SELECT COUNT(*) FROM analysis_target at
                LEFT JOIN verdict v ON v.target_id = at.id
                {where}""",
            params,
        ) as cur:
            row = await cur.fetchone()

    return row[0] if row else 0


async def delete_targets(
    target_ids: list[str],
    db_path: str = DEFAULT_DB_PATH,
) -> dict:
    """Elimina definitivamente uno o più target (``analysis_target``).

    Unica transazione: PRIMA legge quali ID esistono davvero, poi elimina
    solo quelli.  La cascata SQLite (``ON DELETE CASCADE``, attiva via
    ``PRAGMA foreign_keys = ON``) ripulisce state, transition, evidence e
    verdict associati.

    Ritorna ``{"deleted_count": N, "not_found": [...]}`` — ``not_found``
    contiene gli ID richiesti che non esistono (mai creati o già
    eliminati).  Gli ID duplicati in input vengono contati una sola
    volta.  Una lista vuota non tocca nulla e ritorna
    ``{"deleted_count": 0, "not_found": []}`` (il rifiuto esplicito
    della lista vuota è compito della route API).
    """
    ensure_data_dir(db_path)

    # Dedup preservando l'ordine di richiesta
    requested = list(dict.fromkeys(str(i) for i in target_ids))
    if not requested:
        return {"deleted_count": 0, "not_found": []}

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)

        await conn.execute("BEGIN")
        try:
            # PRIMA del delete: quali ID esistono davvero?
            existing: set[str] = set()
            for tid in requested:
                async with conn.execute(
                    "SELECT 1 FROM analysis_target WHERE id = ?", (tid,)
                ) as cur:
                    if await cur.fetchone() is not None:
                        existing.add(tid)

            if existing:
                placeholders = ",".join("?" for _ in existing)
                await conn.execute(
                    f"DELETE FROM analysis_target WHERE id IN ({placeholders})",
                    tuple(existing),
                )

            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    not_found = [tid for tid in requested if tid not in existing]
    return {"deleted_count": len(existing), "not_found": not_found}


async def get_latest_for_url_hash(
    url_hash: str,
    db_path: str = DEFAULT_DB_PATH,
) -> dict | None:
    """Convenience — the most recent complete analysis for *url_hash*.

    Same format as :func:`get_target_by_id`.
    """
    ensure_data_dir(db_path)

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.executescript(DDL)
        conn.row_factory = aiosqlite.Row

        async with conn.execute(
            """SELECT id FROM analysis_target
                WHERE url_hash = ?
                ORDER BY created_at DESC
                LIMIT 1""",
            (url_hash,),
        ) as cur:
            row = await cur.fetchone()

        if row is None:
            return None

        target_id = row["id"]

    return await get_target_by_id(target_id, db_path=db_path)
