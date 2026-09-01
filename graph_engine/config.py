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
con fallback euristico.  Fa eccezione l'endpoint Trellix, che SENZA
``TRELLIX_API_KEY`` risponde 503 (configurazione mancante) e la
dashboard, che resta comunque accessibile col login (admin bootstrap
con password casuale stampata nel log).
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
    "azure_tenant_id",
    "azure_client_id",
    "azure_client_secret",
    "azure_vision_endpoint",
    "azure_vision_key",
    "misp_url",
    "misp_api_key",
    "opencti_url",
    "opencti_api_key",
    "ctlogs_api_key",
    "urlhaus_api_key",
    "trellix_api_key",
    "trellix_api_token",
    "dashboard_admin_user",
    "dashboard_admin_password",
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

    # ── Service principal AAD (autenticazione Foundry) ───────────────
    # Le tre credenziali del service principal usate da
    # ClientSecretCredential.  NOTA: pydantic-settings NON esporta i
    # valori del .env in os.environ — senza questo passaggio esplicito
    # DefaultAzureCredential/EnvironmentCredential non li vedrebbero
    # mai.  Se presenti tutte e tre, il classificatore Foundry usa
    # ClientSecretCredential; altrimenti ripiega su
    # DefaultAzureCredential (az login, managed identity, ecc.).
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

    # ── Azure AI Vision (arricchimento bundle L5) ───────────────────
    # Riusa la risorsa Cognitive Services già attiva
    # (aigpt-pr-it-intelivx-resource, regione italynorth) — nessuna
    # risorsa nuova da creare.  Alimenta OCR (SDK moderna) e Brand
    # Detection (REST legacy v3.2) sugli screenshot degli stati foglia.
    azure_vision_endpoint: Optional[str] = None
    azure_vision_key: Optional[str] = None

    # ── MISP (provider reputazione L2) ──────────────────────────────
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None

    # ── OpenCTI (provider reputazione L2) ───────────────────────────
    opencti_url: Optional[str] = None
    opencti_api_key: Optional[str] = None

    # ── URLhaus (provider reputazione L2, abuse.ch) ──────────────────
    urlhaus_api_key: Optional[str] = None

    # ── ctlogs.dev (certificate transparency L2) ──────────────────────
    # Chiave della REST API di ctlogs.dev (https://api.ctlogs.dev),
    # rilasciata su richiesta.  Con chiave: /v1/domain/{host} +
    # /v1/cert/{id} per la lista SAN (san_dns) dei certificati più
    # recenti.  Senza chiave: endpoint pubblico anonimo, solo
    # cronologia certificati (crt.sh rimosso, 2026-08-27).
    ctlogs_api_key: Optional[str] = None

    # ── Endpoint Trellix (/trellix/analyze) ─────────────────────────
    # API key OBBLIGATORIA (decisione utente 2026-09-01): senza chiave
    # la route risponde 503 (configurazione mancante), mai aperta.
    # ``trellix_api_token`` è il vecchio Bearer opzionale: resta
    # accettato per retrocompatibilità con le integrazioni già attive.
    trellix_api_key: Optional[str] = None
    trellix_api_token: Optional[str] = None

    # ── Bootstrap amministratore dashboard ──────────────────────────
    # Al primo avvio, se la tabella utenti è vuota, viene creato
    # l'admin con queste credenziali.  Se mancano, l'admin viene
    # comunque creato con una password casuale stampata nel log
    # (visibile con ``docker compose logs``).
    dashboard_admin_user: Optional[str] = None
    dashboard_admin_password: Optional[str] = None

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
    def vision_configured(self) -> bool:
        """True se endpoint e key Azure AI Vision sono entrambi presenti."""
        return bool(self.azure_vision_endpoint and self.azure_vision_key)

    @property
    def service_principal_configured(self) -> bool:
        """True se tenant/client/secret del service principal AAD sono
        tutti presenti (→ ClientSecretCredential per Foundry)."""
        return bool(
            self.azure_tenant_id and self.azure_client_id and self.azure_client_secret
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
    def ctlogs_configured(self) -> bool:
        """True se la API key ctlogs.dev è presente (endpoint fisso)."""
        return bool(self.ctlogs_api_key)

    @property
    def urlhaus_configured(self) -> bool:
        """True se la Auth-Key URLhaus è presente.

        A differenza di MISP/OpenCTI non serve una coppia URL+key:
        l'endpoint abuse.ch è fisso e noto (``URLHAUS_API_URL``),
        quindi basta la sola chiave.
        """
        return bool(self.urlhaus_api_key)

    @property
    def trellix_auth_required(self) -> bool:
        """True se è configurata almeno una credenziale Trellix
        (API key o token Bearer legacy) → auth obbligatoria sulla route."""
        return bool(self.trellix_api_key or self.trellix_api_token)


# Istanza singleton — l'unico punto da cui il progetto legge configurazione.
settings = Settings()
