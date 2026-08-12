"""Test per graph_engine.active.jarm — JARM TLS fingerprinting."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from graph_engine.active.jarm import compute_jarm

# Non importiamo il vendor a livello di modulo perché i test lo mockano


class TestJarm:
    """Test unitari per il wrapper JARM (mock del livello socket/TLS)."""

    async def test_returns_valid_hash_on_success(self):
        """JARM calcolato con successo → stringa di 62 caratteri hex."""
        # 62 caratteri esadecimali esatti
        _JARM_62 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        with patch(
            "graph_engine.active.vendor.jarm_reference.jarm_fingerprint",
            return_value=_JARM_62,
        ):
            result = await compute_jarm("example.com", port=443, timeout_s=5.0)

        assert result is not None
        assert len(result) == 62
        # Deve essere esadecimale
        assert all(c in "0123456789abcdef" for c in result)

    async def test_returns_none_on_timeout(self):
        """Timeout → None, mai eccezione."""
        with patch(
            "graph_engine.active.vendor.jarm_reference.jarm_fingerprint",
            side_effect=TimeoutError("timed out"),
        ):
            result = await compute_jarm("unreachable.example.com", timeout_s=0.5)

        assert result is None

    async def test_returns_none_on_connection_refused(self):
        """Connessione rifiutata → None."""
        with patch(
            "graph_engine.active.vendor.jarm_reference.jarm_fingerprint",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = await compute_jarm("closed.example.com")

        assert result is None

    async def test_returns_none_on_all_zeros(self):
        """Tutti zero (server non risponde a nessun hello) → None."""
        with patch(
            "graph_engine.active.vendor.jarm_reference.jarm_fingerprint",
            return_value="0" * 62,
        ):
            result = await compute_jarm("dead.example.com")

        assert result is None

    async def test_returns_none_on_none_result(self):
        """jarm_fingerprint restituisce None → None."""
        with patch(
            "graph_engine.active.vendor.jarm_reference.jarm_fingerprint",
            return_value=None,
        ):
            result = await compute_jarm("example.com")

        assert result is None


class TestJarmIntegration:
    """Test di integrazione: JARM reale contro host stabili."""

    @pytest.mark.integration
    async def test_google_jarm_format(self):
        """Calcola JARM reale contro google.com:443 e verifica il formato."""
        result = await compute_jarm("google.com", port=443, timeout_s=15.0)

        # Potrebbe fallire per ragioni di rete, ma se ritorna qualcosa
        # deve essere nel formato corretto
        if result is not None:
            assert len(result) == 62, f"JARM deve essere 62 caratteri, ottenuto: {len(result)}"
            assert all(c in "0123456789abcdef" for c in result), (
                f"JARM deve essere esadecimale, ottenuto: {result}"
            )
