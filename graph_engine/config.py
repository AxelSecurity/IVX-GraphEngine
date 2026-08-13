"""Configurazione centralizzata dell'engine — single source of truth.

Tutte le chiavi/endpoint API si leggono da qui::

    from graph_engine.config import settings

    if settings.misp_configured:
        ...

Le variabili possono arrivare dall'ambiente di processo o da un file
``.env`` nella root del progetto (vedi ``.env.example`` per l'elenco
completo).  Nessuna credenziale è mai hardcodata nel codice.

Senza alcuna variabile impostata il progetto funziona degradato come
oggi: provider di reputazione extra disabilitati, classificazione L5
con fallback euristico, endpoint Trellix senza autenticazione.
"""

from __future__ import annotations

from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Nomi dei campi snake_case → env var MAIUSCOLE
# (es. ``azure_foundry_endpoint`` ← ``AZURE_FOUNDRY_ENDPOINT``).
_CONFIG_FIELDS = (
    "azure_foundry_endpoint",
    "azure_foundry_agent_id",
    "misp_url",
    "misp_api_key",
    "opencti_url",
    "opencti_api_key",
    "trellix_api_token",
)


class Settings(BaseSettings):
    """Configurazione tipizzata — tutti i campi sono opzionali."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Azure AI Foundry (classificazione L5) ───────────────────────
    azure_foundry_endpoint: Optional[str] = None
    azure_foundry_agent_id: Optional[str] = None

    # ── MISP (provider reputazione L2) ──────────────────────────────
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None

    # ── OpenCTI (provider reputazione L2) ───────────────────────────
    opencti_url: Optional[str] = None
    opencti_api_key: Optional[str] = None

    # ── Endpoint Trellix (/trellix/analyze) ─────────────────────────
    trellix_api_token: Optional[str] = None

    @field_validator(*_CONFIG_FIELDS, mode="before")
    @classmethod
    def _strip_whitespace(cls, v):
        """Rimuove spazi accidentali (es. ``KEY = value`` in ``.env``).

        Preserva il comportamento storico del classificatore Foundry,
        che faceva ``os.getenv(...).strip()``.
        """
        return v.strip() if isinstance(v, str) else v

    # ── Property derivate — sostituiscono i check sparsi ────────────────

    @property
    def foundry_configured(self) -> bool:
        """True se endpoint e agent_id Foundry sono entrambi presenti."""
        return bool(
            self.azure_foundry_endpoint and self.azure_foundry_agent_id
        )

    @property
    def misp_configured(self) -> bool:
        """True se URL e API key MISP sono entrambi presenti."""
        return bool(self.misp_url and self.misp_api_key)

    @property
    def opencti_configured(self) -> bool:
        """True se URL e API key OpenCTI sono entrambi presenti."""
        return bool(self.opencti_url and self.opencti_api_key)

    @property
    def trellix_auth_required(self) -> bool:
        """True se il token Trellix è impostata → auth Bearer richiesta."""
        return bool(self.trellix_api_token)


# Istanza singleton — l'unico punto da cui il progetto legge configurazione.
settings = Settings()
