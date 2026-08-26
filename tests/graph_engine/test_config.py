"""Test della configurazione centralizzata (``graph_engine.config``).

Il modulo espone la classe ``Settings`` e il singleton ``settings``.
Questi test verificano:

1. i campi si leggono dalle variabili d'ambiente (o ``.env``)
2. le property ``*_configured`` richiedono ENTRAMBE le variabili della
   coppia (per Trellix basta il token)
3. senza ``.env`` e senza env vars, ``Settings()`` non solleva errori —
   il progetto funziona degradato come prima
"""

from __future__ import annotations

from graph_engine.config import Settings, settings

# Tutte le variabili gestite da Settings (snake_case → MAIUSCOLE)
ALL_ENV_VARS = {
    "azure_foundry_endpoint": "AZURE_FOUNDRY_ENDPOINT",
    "azure_foundry_agent_id": "AZURE_FOUNDRY_AGENT_ID",
    "azure_tenant_id": "AZURE_TENANT_ID",
    "azure_client_id": "AZURE_CLIENT_ID",
    "azure_client_secret": "AZURE_CLIENT_SECRET",
    "azure_vision_endpoint": "AZURE_VISION_ENDPOINT",
    "azure_vision_key": "AZURE_VISION_KEY",
    "misp_url": "MISP_URL",
    "misp_api_key": "MISP_API_KEY",
    "opencti_url": "OPENCTI_URL",
    "opencti_api_key": "OPENCTI_API_KEY",
    "urlhaus_api_key": "URLHAUS_API_KEY",
    "trellix_api_token": "TRELLIX_API_TOKEN",
}


def _clean_settings(**overrides) -> Settings:
    """Istanza Settings isolata, con tutti i campi a None.

    ``_env_file=None`` disabilita la lettura di un eventuale ``.env``
    reale nella root; i kwargs espliciti hanno priorità sulle variabili
    d'ambiente di processo.
    """
    kwargs = {field: None for field in ALL_ENV_VARS}
    kwargs.update(overrides)
    return Settings(_env_file=None, **kwargs)


class TestSettingsFields:
    def test_fields_read_from_environment(self, monkeypatch):
        """I campi si legano alle rispettive variabili d'ambiente."""
        monkeypatch.setenv(
            "AZURE_FOUNDRY_ENDPOINT", "https://foundry.example.com"
        )
        monkeypatch.setenv("AZURE_FOUNDRY_AGENT_ID", "agent-123")
        monkeypatch.setenv("MISP_URL", "https://misp.example.com")
        monkeypatch.setenv("MISP_API_KEY", "misp-key")
        monkeypatch.setenv("OPENCTI_URL", "https://opencti.example.com")
        monkeypatch.setenv("OPENCTI_API_KEY", "opencti-key")
        monkeypatch.setenv("URLHAUS_API_KEY", "urlhaus-key")
        monkeypatch.setenv("TRELLIX_API_TOKEN", "trellix-token")

        s = Settings(_env_file=None)

        assert s.azure_foundry_endpoint == "https://foundry.example.com"
        assert s.azure_foundry_agent_id == "agent-123"
        assert s.misp_url == "https://misp.example.com"
        assert s.misp_api_key == "misp-key"
        assert s.opencti_url == "https://opencti.example.com"
        assert s.opencti_api_key == "opencti-key"
        assert s.urlhaus_api_key == "urlhaus-key"
        assert s.trellix_api_token == "trellix-token"

    def test_whitespace_stripped_from_values(self, monkeypatch):
        """Spazi accidentali (es. ``KEY = value`` in .env) vengono rimossi —
        preserva il comportamento storico di ``os.getenv(...).strip()``
        del classificatore Foundry."""
        monkeypatch.setenv(
            "AZURE_FOUNDRY_ENDPOINT", "  https://foundry.example.com  "
        )
        s = Settings(_env_file=None)
        assert s.azure_foundry_endpoint == "https://foundry.example.com"

    def test_no_config_does_not_raise(self, monkeypatch):
        """Senza .env e senza env vars, Settings() non solleva errori
        e tutti i campi sono None."""
        for env_var in ALL_ENV_VARS.values():
            monkeypatch.delenv(env_var, raising=False)

        s = Settings(_env_file=None)
        for field in ALL_ENV_VARS:
            assert getattr(s, field) is None

    def test_extra_env_vars_ignored(self, monkeypatch):
        """Variabili non note (es. di altri strumenti) non causano errori
        e non diventano campi del modello (extra="ignore")."""
        monkeypatch.setenv("SOME_UNRELATED_VAR", "x")
        s = Settings(_env_file=None)
        assert not hasattr(s, "some_unrelated_var")


class TestConfiguredProperties:
    def test_all_present(self):
        """Tutte le coppie presenti → tutte le property True."""
        s = _clean_settings(
            azure_foundry_endpoint="https://foundry.example.com",
            azure_foundry_agent_id="agent-1",
            misp_url="https://misp.example.com",
            misp_api_key="k1",
            opencti_url="https://opencti.example.com",
            opencti_api_key="k2",
            urlhaus_api_key="k3",
            trellix_api_token="t1",
        )
        assert s.foundry_configured is True
        assert s.misp_configured is True
        assert s.opencti_configured is True
        assert s.urlhaus_configured is True
        assert s.trellix_auth_required is True

    def test_only_one_of_pair_is_false(self):
        """Una sola variabile della coppia NON basta — deve essere False."""
        s = _clean_settings(
            azure_foundry_endpoint="https://foundry.example.com"
        )
        assert s.foundry_configured is False

        s = _clean_settings(azure_foundry_agent_id="agent-1")
        assert s.foundry_configured is False

        s = _clean_settings(misp_url="https://misp.example.com")
        assert s.misp_configured is False

        s = _clean_settings(misp_api_key="k1")
        assert s.misp_configured is False

        s = _clean_settings(opencti_url="https://opencti.example.com")
        assert s.opencti_configured is False

        s = _clean_settings(opencti_api_key="k2")
        assert s.opencti_configured is False

    def test_none_present(self):
        """Nessuna variabile → tutte le property False, nessun errore."""
        s = _clean_settings()
        assert s.foundry_configured is False
        assert s.misp_configured is False
        assert s.opencti_configured is False
        assert s.urlhaus_configured is False
        assert s.trellix_auth_required is False

    def test_trellix_single_field(self):
        """Trellix ha un solo campo: token presente → auth richiesta."""
        s = _clean_settings(trellix_api_token="t1")
        assert s.trellix_auth_required is True

    def test_urlhaus_single_field(self):
        """URLhaus ha un solo campo (endpoint fisso): chiave presente →
        configurato."""
        s = _clean_settings(urlhaus_api_key="k")
        assert s.urlhaus_configured is True

    def test_empty_string_not_configured(self):
        """Stringa vuota (es. ``TRELLIX_API_TOKEN=`` in .env) → non
        configurata — identico al vecchio ``if token:``."""
        s = _clean_settings(trellix_api_token="", urlhaus_api_key="")
        assert s.trellix_auth_required is False
        assert s.urlhaus_configured is False

    def test_service_principal_requires_all_three(self):
        """Service principal AAD: servono TUTTE e tre le credenziali —
        una coppia parziale NON configura ClientSecretCredential."""
        s = _clean_settings(
            azure_tenant_id="tenant-1",
            azure_client_id="client-1",
            azure_client_secret="secret-1",
        )
        assert s.service_principal_configured is True

        s = _clean_settings(azure_tenant_id="tenant-1", azure_client_id="client-1")
        assert s.service_principal_configured is False

        s = _clean_settings(azure_client_id="client-1")
        assert s.service_principal_configured is False


class TestModuleSingleton:
    def test_singleton_is_settings_instance(self):
        """Il singleton a livello di modulo è un'istanza di Settings."""
        assert isinstance(settings, Settings)

    def test_singleton_exposes_properties(self):
        """Le property esistono sul singleton (il valore dipende
        dall'ambiente di processo)."""
        assert isinstance(settings.foundry_configured, bool)
        assert isinstance(settings.misp_configured, bool)
        assert isinstance(settings.opencti_configured, bool)
        assert isinstance(settings.urlhaus_configured, bool)
        assert isinstance(settings.trellix_auth_required, bool)
        assert isinstance(settings.vision_configured, bool)
        assert isinstance(settings.service_principal_configured, bool)
