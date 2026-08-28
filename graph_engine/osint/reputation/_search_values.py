"""Costruzione condivisa dei valori candidati per le query di reputazione.

Estratto da ``misp.py`` per essere riusato dai provider (MISP, OpenCTI)
che interrogano feed/piattaforme di minacce con URL, hostname, dominio
registrabile e IP: una sola lista di candidati, stesso ordine, stessa
dedup — nessuna reimplementazione per provider.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse


def dedupe_values(values: list[str]) -> list[str]:
    """Rimuove duplicati e valori vuoti preservando l'ordine."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        v = v.strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def build_search_values(
    url: str,
    known_ips: Optional[list[str]],
) -> list[str]:
    """Costruisce la lista di valori candidati per una query di reputazione.

    Candidati: URL completo, hostname, dominio registrabile e, se
    presenti, gli IP noti risolti da L2.  Il dominio registrabile
    riusa ``_registrable_domain`` di L1 (lexical/typosquat) — stessa
    funzione già corretta con tldextract, nessuna terza
    reimplementazione dell'estrazione eTLD+1.
    """
    from graph_engine.lexical.typosquat import _registrable_domain

    candidates = [url]
    hostname = (urlparse(url).hostname or "").lower()
    if hostname:
        candidates.append(hostname)
        reg_domain = _registrable_domain(hostname)
        if reg_domain and reg_domain != hostname:
            candidates.append(reg_domain)
    if known_ips:
        candidates.extend(ip for ip in known_ips if isinstance(ip, str))
    return dedupe_values(candidates)
