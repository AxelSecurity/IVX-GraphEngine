"""Pagine d'avviso di sicurezza dei provider (Cloudflare, Google Safe Browsing).

Quando un provider ha già segnalato un sito, al posto del contenuto
serve una propria pagina d'avviso (es. Cloudflare "Suspected Phishing"
o "Suspected Malware"). Per il motore è un segnale forte e verificato:
il sito è stato riconosciuto malevolo da chi lo ospita o lo protegge.
Senza questa regola il modello vedeva solo una pagina "pulita" del
provider (caso reale: pagina Cloudflare "Suspected Malware" giudicata
safe con confidenza 0.9).

Il rilevamento è volutamente stretto, per non scambiare un articolo che
parla di phishing per un avviso:

- vale solo per gli stati del dominio analizzato (root o stesso host
  dell'URL in ingresso), mai per siti terzi raggiunti con i click;
- Cloudflare: titolo "Suspected phishing/malware ... Cloudflare"
  oppure la frase dell'avviso "has been reported for potentially ..."
  insieme alla menzione di Cloudflare;
- Google Safe Browsing: le frasi dell'interstitial ("Deceptive site
  ahead", "The site ahead contains malware/harmful programs").
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

_CLOUDFLARE_TITLE_MARKERS = {
    "suspected phishing": "phishing",
    "suspected malware": "malware",
}
_CLOUDFLARE_TEXT_MARKERS = {
    "has been reported for potentially phishing": "phishing",
    "has been reported for potentially distributing malware": "malware",
    "suspected phishing site ahead": "phishing",
}
_SAFE_BROWSING_MARKERS = {
    "deceptive site ahead": "phishing",
    "the site ahead contains malware": "malware",
    "the site ahead contains harmful programs": "malware",
}


def _host(url: Optional[str]) -> str:
    return (urlparse(url or "").hostname or "").lower().removeprefix("www.")


def _match(state: dict) -> Optional[tuple[str, str, str]]:
    """(provider, kind, frase trovata) se *state* è una pagina d'avviso."""
    title = (state.get("title") or "").lower()
    body = " ".join(
        (state.get(key) or "") for key in ("visible_text", "ocr_text")
    ).lower()
    everything = f"{title} {body}"

    if "cloudflare" in everything:
        for marker, kind in _CLOUDFLARE_TITLE_MARKERS.items():
            if marker in title:
                return "Cloudflare", kind, marker
        for marker, kind in _CLOUDFLARE_TEXT_MARKERS.items():
            if marker in body:
                return "Cloudflare", kind, marker
    for marker, kind in _SAFE_BROWSING_MARKERS.items():
        if marker in everything:
            return "Google Safe Browsing", kind, marker
    return None


def detect_provider_warning(bundle: dict) -> Optional[dict]:
    """Prima pagina d'avviso trovata sul dominio analizzato, o None.

    Ritorna ``{"provider", "kind" ("phishing"|"malware"), "marker",
    "state_url"}``.
    """
    target_hosts = {
        _host(bundle.get("input_url")),
        _host(bundle.get("canonical_url")),
    } - {""}
    for state in bundle.get("states", []):
        if not isinstance(state, dict):
            continue
        on_target = state.get("depth") == 0 or _host(state.get("url")) in target_hosts
        if not on_target:
            continue
        found = _match(state)
        if found is not None:
            provider, kind, marker = found
            return {
                "provider": provider,
                "kind": kind,
                "marker": marker,
                "state_url": state.get("url"),
            }
    return None


def kit_family_for(warning: dict) -> str:
    """Valore di ``Verdict.kit_family`` che codifica provider e tipo."""
    return f"provider-warning:{warning['provider']}:{warning['kind']}"


def parse_kit_family(kit_family: Optional[str]) -> Optional[tuple[str, str]]:
    """(provider, kind) da un kit_family prodotto da ``kit_family_for``."""
    if not kit_family or not kit_family.startswith("provider-warning:"):
        return None
    parts = kit_family.split(":", 2)
    if len(parts) != 3:
        return None
    return parts[1], parts[2]
