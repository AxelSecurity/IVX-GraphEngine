"""Configurazione dei log (graph_engine.api.app.configure_logging)."""

from __future__ import annotations

import logging

from graph_engine.api.app import _HealthCheckAccessFilter, configure_logging


def _access_record(path: str, status: int) -> logging.LogRecord:
    return logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 0,
        '%s - "%s %s HTTP/%s" %d', ("127.0.0.1:5000", "GET", path, "1.1", status), None,
    )


class TestHealthCheckFilter:
    def test_successful_health_dropped(self):
        assert _HealthCheckAccessFilter().filter(_access_record("/health", 200)) is False

    def test_failed_health_kept(self):
        assert _HealthCheckAccessFilter().filter(_access_record("/health", 503)) is True

    def test_other_requests_kept(self):
        f = _HealthCheckAccessFilter()
        assert f.filter(_access_record("/api/v1/analyze?url=x", 200)) is True
        assert f.filter(_access_record("/analyses/abc", 200)) is True


class TestConfigureLogging:
    def test_azure_never_below_warning(self):
        configure_logging("DEBUG")
        assert logging.getLogger("azure").level == logging.WARNING
        configure_logging("ERROR")
        assert logging.getLogger("azure").level == logging.ERROR
        configure_logging("INFO")

    def test_level_from_name_and_unknown_falls_back_to_info(self):
        assert configure_logging("debug") == logging.DEBUG
        assert configure_logging("verbosissimo") == logging.INFO
        configure_logging("INFO")

    def test_filter_installed_once(self):
        configure_logging("INFO")
        configure_logging("INFO")
        filters = [f for f in logging.getLogger("uvicorn.access").filters
                   if isinstance(f, _HealthCheckAccessFilter)]
        assert len(filters) == 1
