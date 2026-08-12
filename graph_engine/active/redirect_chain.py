"""Tracciamento manuale della catena di redirect HTTP.

Segue i redirect passo per passo con ``follow_redirects=False``, registrando
per ogni hop: status_code, location header, nomi dei cookie (NON i valori),
e server header. Non solleva mai eccezioni verso il chiamante.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx


# ---------------------------------------------------------------------------
# Status code che consideriamo "redirect"
# ---------------------------------------------------------------------------

_REDIRECT_STATUSES: frozenset = frozenset({301, 302, 303, 307, 308})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def trace_redirect_chain(
    url: str,
    client: httpx.AsyncClient,
    max_hops: int = 10,
) -> dict:
    """Segue MANUALMENTE i redirect HTTP e restituisce la catena completa.

    Args:
        url: URL di partenza.
        client: Client ``httpx.AsyncClient`` già configurato (con timeout).
        max_hops: Numero massimo di redirect da seguire (default 10).

    Returns:
        dict con chiavi:
        - ``hops``: list[dict] — un elemento per ogni hop, incluso l'ultimo
          (quello che NON è un redirect). Ogni hop ha:
          ``status_code``, ``url``, ``location`` (se redirect),
          ``server`` (se presente), ``cookies`` (lista di NOMI, mai valori),
          ``error`` (solo se la richiesta è fallita)
        - ``final_url``: str — ultimo URL raggiunto
        - ``hop_count``: int — numero totale di hop
        - ``redirect_count``: int — numero di redirect (hop con status 3xx)
        - ``truncated``: bool — True se tagliato a max_hops
    """
    hops: list[dict] = []
    current_url = url
    redirect_count = 0
    truncated = False

    for _ in range(max_hops):
        hop: dict = {
            "status_code": None,
            "url": current_url,
        }

        try:
            response = await client.get(
                current_url,
                follow_redirects=False,
            )
            hop["status_code"] = response.status_code

            # Server header
            server = response.headers.get("server")
            if server:
                hop["server"] = server

            # Cookie names ONLY (mai i valori)
            set_cookie_headers = response.headers.get_list("set-cookie")
            if set_cookie_headers:
                cookie_names = []
                for sc in set_cookie_headers:
                    # Il nome del cookie è tutto prima del primo "="
                    name = sc.split("=", 1)[0].strip()
                    if name:
                        cookie_names.append(name)
                if cookie_names:
                    hop["cookies"] = cookie_names

            hops.append(hop)

            # Se non è un redirect, abbiamo finito
            if response.status_code not in _REDIRECT_STATUSES:
                return {
                    "hops": hops,
                    "final_url": current_url,
                    "hop_count": len(hops),
                    "redirect_count": redirect_count,
                    "truncated": False,
                }

            # È un redirect — prendi la Location
            location = response.headers.get("location")
            if not location:
                # Redirect senza Location — impossibile proseguire
                return {
                    "hops": hops,
                    "final_url": current_url,
                    "hop_count": len(hops),
                    "redirect_count": redirect_count,
                    "truncated": False,
                }

            hop["location"] = location
            redirect_count += 1

            # Risolvi URL relativo → assoluto
            current_url = urljoin(current_url, location)

        except httpx.TimeoutException:
            hop["error"] = "timeout"
            hops.append(hop)
            return {
                "hops": hops,
                "final_url": current_url,
                "hop_count": len(hops),
                "redirect_count": redirect_count,
                "truncated": False,
            }
        except Exception as exc:
            hop["error"] = str(exc)
            hops.append(hop)
            return {
                "hops": hops,
                "final_url": current_url,
                "hop_count": len(hops),
                "redirect_count": redirect_count,
                "truncated": False,
            }

    # Abbiamo raggiunto max_hops — l'ultimo hop potrebbe essere ancora un redirect
    truncated = True
    return {
        "hops": hops,
        "final_url": current_url,
        "hop_count": len(hops),
        "redirect_count": redirect_count,
        "truncated": True,
    }
