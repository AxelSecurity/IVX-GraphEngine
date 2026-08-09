"""Exploration budget — limits BFS breadth, depth, and wall-clock time."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Budget:
    """Limits applied during BFS exploration.

    Attributes:
        max_depth:  Maximum distance from root state (root = depth 0).
        max_nodes:  Hard limit on total States created across the whole target.
        timeout_s:  Wall-clock seconds after which exploration is terminated.
    """

    max_depth: int = 6
    max_nodes: int = 40
    timeout_s: int = 180
