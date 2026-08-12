"""Favicon hash — impronta stile Shodan/Censys.

L'algoritmo è ESATTAMENTE:

1. Scarica i byte grezzi del favicon
2. ``encoded = base64.encodebytes(raw_bytes)`` — con a-capo MIME ogni 76
   caratteri (NON ``base64.b64encode`` che produce una stringa continua)
3. ``h = mmh3.hash(encoded, seed=0, signed=True)`` — MurmurHash3 32-bit
   CON segno (signed int). I parametri sono ESPLICITI per blindare la
   convenzione Shodan/Censys contro futuri cambi di default di mmh3.
   (mmh3 v5.x ha rimosso ``hash32()`` — non ci fidiamo dei default.)

Nota: Shodan pubblica il valore come intero CON segno a 32-bit.
``mmh3.hash`` con ``signed=True`` restituisce già un signed int,
quindi nessuna conversione necessaria.

LIMITAZIONE ATTUALE: per semplicità in questa fase, proviamo SOLO
``/favicon.ico`` sulla root del dominio. Il parsing del link
``<link rel="icon">`` dal body HTML non è ancora implementato.
"""

from __future__ import annotations

import base64
from typing import Optional
from urllib.parse import urljoin

import httpx
import mmh3


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_favicon_hash(
    url: str,
    client: httpx.AsyncClient,
) -> Optional[dict]:
    """Scarica il favicon e calcola l'hash stile Shodan/Censys.

    Per ora prova SOLO ``/favicon.ico`` sulla root del dominio.
    Vedi docstring del modulo per i dettagli dell'algoritmo.

    Args:
        url: URL del sito target (usato per costruire l'URL del favicon).
        client: Client ``httpx.AsyncClient`` già configurato.

    Returns:
        dict con ``favicon_hash`` (int signed 32-bit) e
        ``favicon_size_bytes`` (int), oppure None se il favicon
        non è stato trovato o c'è stato un errore.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

    try:
        response = await client.get(favicon_url, follow_redirects=True)
        if response.status_code != 200:
            return None

        raw_bytes = response.content
        if not raw_bytes or len(raw_bytes) == 0:
            return None

        # Algoritmo ESATTO Shodan/Censys:
        # 1. base64.encodebytes (MIME-style, con a-capo ogni 76 caratteri)
        # 2. mmh3.hash (32-bit signed MurmurHash3 — API mmh3 >= 5.0)
        encoded = base64.encodebytes(raw_bytes)
        # Parametri ESPLICITI (seed=0, signed=True): blindano la convenzione
        # Shodan/Censys contro futuri cambi di default della libreria mmh3.
        # v5.x ha già rimosso hash32() — non vogliamo che un cambio di default
        # in v6.x produca hash sbagliati senza alcun errore visibile.
        favicon_hash = mmh3.hash(encoded, seed=0, signed=True)

        return {
            "favicon_hash": favicon_hash,
            "favicon_size_bytes": len(raw_bytes),
        }

    except Exception:
        return None
