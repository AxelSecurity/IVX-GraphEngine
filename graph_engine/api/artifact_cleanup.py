"""Pulizia artefatti su disco per i target eliminati.

La rimozione delle cartelle ``data/graph_artifacts/<target_id>/`` va
chiamata SOLO **dopo** che la cancellazione SQLite è confermata (commit
riuscito) — mai prima: se il delete del DB fallisse a metà, gli
artefatti devono restare intatti.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger("graph_engine.api")


def remove_artifact_dirs(target_ids: list[str], artifact_root: Path) -> None:
    """Rimuove ``artifact_root/<target_id>/`` per ogni ID eliminato con successo.

    ``shutil.rmtree(..., ignore_errors=True)``: la cartella potrebbe non
    esistere affatto (analisi con ``capture_artifacts=False``) — non è un
    errore e la funzione non solleva.

    Difesa in profondità: il path risolto deve restare dentro
    ``artifact_root``, altrimenti l'ID viene saltato (mai cancellare
    fuori dalla root degli artefatti).
    """
    root = Path(artifact_root).resolve()
    for tid in target_ids:
        path = (root / tid).resolve()
        if not path.is_relative_to(root):
            logger.warning(
                "Skip pulizia artefatti: path fuori da artifact_root (%s)", tid
            )
            continue
        shutil.rmtree(path, ignore_errors=True)
        logger.info("Artefatti rimossi per target %s", tid)
