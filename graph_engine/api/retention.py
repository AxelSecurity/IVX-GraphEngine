"""Retention dei file su disco — tiene sotto controllo la crescita di ``data/``.

Ogni analisi salva screenshot, DOM e HAR per stato in
``data/graph_artifacts/<target_id>/`` (da ~1 a ~15 MB per analisi) e la
cache OSINT scrive un file per dominio interrogato: senza pulizia il
disco cresce senza limite.

Politica:

- **Artefatti** (``graph_artifacts/<target_id>/``): cancellati quando
  il file più recente della cartella ha più di ``ARTIFACT_RETENTION_DAYS``
  giorni (default 30; ``0`` = mai).  Verdetti, grafo, evidenze e storico
  restano nel DB: la dashboard mostra l'analisi senza immagini (elenca
  solo i file ancora presenti).
- **Cache OSINT** (``osint_cache/<provider>/*.json``): cancellati i file
  più vecchi del TTL più lungo usato dalla cache (30 giorni): sono
  comunque scaduti e non verrebbero più letti.

Il job gira nel processo dell'API (lifespan): una prima passata poco
dopo l'avvio, poi ogni ``_INTERVAL_S``.  Il lavoro su disco va in un
thread per non bloccare l'event loop.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from graph_engine.config import settings
from graph_engine.osint.cache import TTL_IANA_BOOTSTRAP

logger = logging.getLogger("graph_engine.api.retention")

_FIRST_RUN_DELAY_S = 60
_INTERVAL_S = 24 * 3600
# TTL massimo della cache OSINT: oltre, un file non viene più letto.
_OSINT_MAX_AGE_S = TTL_IANA_BOOTSTRAP


@dataclass
class RetentionReport:
    artifact_dirs_removed: int = 0
    osint_files_removed: int = 0
    bytes_freed: int = 0


def _tree_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _newest_mtime(target_dir: Path) -> float:
    """mtime più recente tra la cartella del target e le cartelle di stato.

    Le cartelle di stato vengono create (e i loro file scritti) durante
    l'analisi: il loro mtime è l'istante dell'ultima scrittura.
    """
    newest = target_dir.stat().st_mtime
    for child in target_dir.iterdir():
        try:
            newest = max(newest, child.stat().st_mtime)
        except OSError:
            continue
    return newest


def purge_artifacts(
    artifact_root: Path, max_age_days: int, now: float | None = None,
) -> RetentionReport:
    """Rimuove le cartelle di artefatti più vecchie di *max_age_days*."""
    report = RetentionReport()
    if max_age_days <= 0:
        return report
    root = Path(artifact_root)
    if not root.is_dir():
        return report
    cutoff = (now if now is not None else time.time()) - max_age_days * 86400
    resolved_root = root.resolve()
    for target_dir in root.iterdir():
        try:
            if not target_dir.is_dir() or target_dir.is_symlink():
                continue
            if not target_dir.resolve().is_relative_to(resolved_root):
                continue
            if _newest_mtime(target_dir) >= cutoff:
                continue
            size = _tree_size(target_dir)
            shutil.rmtree(target_dir)
        except OSError as exc:
            logger.warning("Retention: impossibile rimuovere %s: %s", target_dir, exc)
            continue
        report.artifact_dirs_removed += 1
        report.bytes_freed += size
    return report


def purge_osint_cache(
    cache_root: Path, max_age_s: float = _OSINT_MAX_AGE_S, now: float | None = None,
) -> RetentionReport:
    """Rimuove i file di cache OSINT più vecchi di *max_age_s*."""
    report = RetentionReport()
    root = Path(cache_root)
    if not root.is_dir():
        return report
    cutoff = (now if now is not None else time.time()) - max_age_s
    for path in root.glob("*/*.json"):
        try:
            stat = path.stat()
            if stat.st_mtime >= cutoff:
                continue
            path.unlink()
        except OSError:
            continue
        report.osint_files_removed += 1
        report.bytes_freed += stat.st_size
    return report


def run_retention(artifact_root: Path, cache_root: Path) -> RetentionReport:
    """Una passata completa di retention (sincrona)."""
    artifacts = purge_artifacts(artifact_root, settings.artifact_retention_days)
    osint = purge_osint_cache(cache_root)
    report = RetentionReport(
        artifact_dirs_removed=artifacts.artifact_dirs_removed,
        osint_files_removed=osint.osint_files_removed,
        bytes_freed=artifacts.bytes_freed + osint.bytes_freed,
    )
    if report.artifact_dirs_removed or report.osint_files_removed:
        logger.info(
            "Retention: rimossi artefatti di %d analisi e %d file di cache "
            "OSINT (%.1f MB liberati)",
            report.artifact_dirs_removed,
            report.osint_files_removed,
            report.bytes_freed / 1_048_576,
        )
    return report


async def retention_loop(artifact_root: Path, cache_root: Path) -> None:
    """Job periodico: prima passata dopo l'avvio, poi ogni 24 ore."""
    await asyncio.sleep(_FIRST_RUN_DELAY_S)
    while True:
        try:
            await asyncio.to_thread(run_retention, artifact_root, cache_root)
        except Exception:  # noqa: BLE001 — il job non deve mai morire
            logger.exception("Retention: passata fallita")
        await asyncio.sleep(_INTERVAL_S)
