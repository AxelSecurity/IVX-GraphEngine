"""JARM TLS fingerprinting — wrapper asincrono.

Usa l'implementazione vendorizzata di Salesforce
(``graph_engine.active.vendor.jarm_reference``) che invia 10 TLS Client
Hello con parametri variati e produce un fuzzy hash a 62 caratteri.

La computazione JARM è sincrona e basata su socket grezzi — questo modulo
la wrappa con ``asyncio.to_thread`` per non bloccare l'event loop.
"""

from __future__ import annotations

import asyncio
from typing import Optional


async def compute_jarm(
    hostname: str,
    port: int = 443,
    timeout_s: float = 10.0,
) -> Optional[str]:
    """Calcola il JARM fingerprint per *hostname:port*.

    Esegue la computazione (socket sincroni) in un thread separato
    tramite ``asyncio.to_thread``, con timeout esplicito.

    Args:
        hostname: Hostname o IP del server TLS.
        port: Porta TCP (default 443).
        timeout_s: Timeout complessivo in secondi (default 10).

    Returns:
        Stringa JARM di 62 caratteri esadecimali, o None in caso di
        qualunque fallimento (rete, handshake, timeout).
    """
    from graph_engine.active.vendor.jarm_reference import jarm_fingerprint

    try:
        # asyncio.to_thread è disponibile da Python 3.9+
        result = await asyncio.wait_for(
            asyncio.to_thread(
                jarm_fingerprint,
                hostname,
                port,
                timeout_s,
            ),
            timeout=timeout_s + 2.0,  # margine extra per l'overhead del thread
        )
        # Il vendor restituisce None per fallimenti; se per qualche
        # ragione restituisce tutti zeri, consideralo fallimento
        if result is not None and result == "0" * 62:
            return None
        return result
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None
