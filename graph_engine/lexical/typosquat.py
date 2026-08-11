"""Typosquat detection via Damerau-Levenshtein distance.

Confronta il dominio registrabile di un hostname contro una lista
curata di domini legittimi (brands.yaml).  Distanza <= 2 è sospetta;
distanza 0 (dominio identico) non conta — è il sito vero.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Damerau-Levenshtein (Optimal String Alignment)
# ---------------------------------------------------------------------------


def damerau_levenshtein(a: str, b: str) -> int:
    """Distanza di edit ristretta (inserimento, cancellazione,
    sostituzione, trasposizione di caratteri adiacenti).

    Complessità O(m*n), pura Python — nessuna dipendenza esterna.
    """
    m, n = len(a), len(b)
    # Matrice (m+1) × (n+1)
    d = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        d[i][0] = i
    for j in range(n + 1):
        d[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # cancellazione
                d[i][j - 1] + 1,       # inserimento
                d[i - 1][j - 1] + cost,  # sostituzione
            )
            # Trasposizione di caratteri adiacenti
            if (
                i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[m][n]


# ---------------------------------------------------------------------------
# Estrazione dominio registrabile
# ---------------------------------------------------------------------------

# TLD a due componenti comuni: il dominio registrabile richiede 3 label
_TWO_PART_TLDS = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "org.br", "net.br", "gov.br",
})


def _registrable_domain(hostname: str) -> str:
    """Restituisce il dominio registrabile (eTLD+1) da un hostname.

    Esempi:
        login.inps.gov.it  →  inps.gov.it
        evil.example.com   →  example.com
        example.com        →  example.com

    Per TLD semplici (.com, .it, …) prende le ultime 2 label;
    per TLD a due componenti noti (.co.uk, …) prende le ultime 3.
    """
    hostname = hostname.strip(".").lower()
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname

    # TLD a due componenti → servono 3 label per il dominio registrabile
    if len(labels) >= 3:
        candidate_tld = f"{labels[-2]}.{labels[-1]}"
        if candidate_tld in _TWO_PART_TLDS:
            return f"{labels[-3]}.{candidate_tld}"

    # TLD semplice: ultime 2 label
    return f"{labels[-2]}.{labels[-1]}"


# ---------------------------------------------------------------------------
# Brand loader
# ---------------------------------------------------------------------------

def _load_brands(path: str) -> list[dict]:
    """Carica la lista brand da un file YAML."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        raise ValueError(f"brands.yaml deve essere una lista, trovato {type(data)}")
    return data


# ---------------------------------------------------------------------------
# Typosquat check
# ---------------------------------------------------------------------------

_DEFAULT_BRANDS_PATH = str(
    Path(__file__).resolve().parent / "data" / "brands.yaml"
)


def check_typosquat(
    hostname: str,
    brands_path: str = _DEFAULT_BRANDS_PATH,
) -> Optional[dict]:
    """Confronta il dominio registrabile di *hostname* contro i domini
    noti in *brands_path*.

    Ritorna il match più vicino con distanza Damerau-Levenshtein <= 2,
    oppure ``None`` se nessun brand è entro soglia o se il dominio è
    IDENTICO a un dominio noto (sito legittimo, non typosquat).

    Il dizionario restituito ha chiavi ``brand``, ``matched_domain``,
    ``distance``.
    """
    reg_domain = _registrable_domain(hostname)
    brands = _load_brands(brands_path)

    best: Optional[dict] = None
    best_dist = 999

    for entry in brands:
        for known in entry["domains"]:
            known = known.lower()
            # Dominio identico → non è typosquat
            if reg_domain == known:
                continue
            dist = damerau_levenshtein(reg_domain, known)
            if dist <= 2 and dist < best_dist:
                best_dist = dist
                best = {
                    "brand": entry["brand"],
                    "matched_domain": known,
                    "distance": dist,
                }

    return best
