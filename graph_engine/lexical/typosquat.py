"""Typosquat detection via Damerau-Levenshtein distance.

Confronta il dominio registrabile di un hostname contro una lista
curata di domini legittimi (brands.yaml).  Distanza <= 2 è sospetta;
distanza 0 (dominio identico) non conta — è il sito vero.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import tldextract
import yaml

# ---------------------------------------------------------------------------
# Public Suffix List extractor — offline, nessuna richiesta di rete
# ---------------------------------------------------------------------------

_extractor = tldextract.TLDExtract(
    suffix_list_urls=None,         # no network — usa solo snapshot PSL incluso
    include_psl_private_domains=True,  # include gov.it, com.mx, co.in, ecc.
    fallback_to_snapshot=True,
    cache_dir=None,                # nessuna cache su disco
)

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

def _registrable_domain(hostname: str) -> str:
    """Restituisce il dominio registrabile (eTLD+1) da un hostname.

    Usa tldextract con la Public Suffix List ufficiale, senza richieste
    di rete — solo lo snapshot PSL incluso nel pacchetto.

    Esempi:
        login.inps.gov.it   →  inps.gov.it
        evil.example.com    →  example.com
        example.com         →  example.com
        example.co.uk       →  example.co.uk
        keyimportacao.com.br → keyimportacao.com.br
    """
    hostname = hostname.strip(".").lower()
    result = _extractor(hostname)
    if result.suffix:
        return f"{result.domain}.{result.suffix}"
    # Fallback: hostname senza suffisso riconosciuto (es. IP, TLD sconosciuto)
    return hostname


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
