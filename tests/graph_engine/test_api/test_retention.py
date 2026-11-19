"""Retention dei file su disco (graph_engine.api.retention)."""

from __future__ import annotations

import os
import time

from graph_engine.api import retention
from graph_engine.config import settings

_DAY = 86400


def _make_artifacts(root, target_id: str, age_days: float, now: float) -> None:
    state_dir = root / target_id / "state-1"
    state_dir.mkdir(parents=True)
    (state_dir / "screenshot.png").write_bytes(b"x" * 1000)
    ts = now - age_days * _DAY
    for p in (state_dir / "screenshot.png", state_dir, root / target_id):
        os.utime(p, (ts, ts))


class TestPurgeArtifacts:
    def test_old_removed_recent_kept(self, tmp_path):
        now = time.time()
        _make_artifacts(tmp_path, "old", 31, now)
        _make_artifacts(tmp_path, "recent", 2, now)

        report = retention.purge_artifacts(tmp_path, 30, now=now)

        assert not (tmp_path / "old").exists()
        assert (tmp_path / "recent").exists()
        assert report.artifact_dirs_removed == 1
        assert report.bytes_freed == 1000

    def test_zero_days_disables(self, tmp_path):
        now = time.time()
        _make_artifacts(tmp_path, "old", 400, now)
        report = retention.purge_artifacts(tmp_path, 0, now=now)
        assert (tmp_path / "old").exists()
        assert report.artifact_dirs_removed == 0

    def test_recent_state_keeps_whole_analysis(self, tmp_path):
        """Basta una cartella di stato recente per tenere l'analisi."""
        now = time.time()
        _make_artifacts(tmp_path, "mixed", 60, now)
        fresh = tmp_path / "mixed" / "state-2"
        fresh.mkdir()
        report = retention.purge_artifacts(tmp_path, 30, now=now)
        assert (tmp_path / "mixed").exists()
        assert report.artifact_dirs_removed == 0

    def test_missing_root_is_noop(self, tmp_path):
        report = retention.purge_artifacts(tmp_path / "nope", 30)
        assert report.artifact_dirs_removed == 0


class TestPurgeOsintCache:
    def test_only_expired_files_removed(self, tmp_path):
        now = time.time()
        old = tmp_path / "rdap" / "old.json"
        new = tmp_path / "rdap" / "new.json"
        old.parent.mkdir()
        old.write_text("{}")
        new.write_text("{}")
        ts = now - 31 * _DAY
        os.utime(old, (ts, ts))

        report = retention.purge_osint_cache(tmp_path, max_age_s=30 * _DAY, now=now)

        assert not old.exists()
        assert new.exists()
        assert report.osint_files_removed == 1


class TestRunRetention:
    def test_uses_configured_days(self, tmp_path, monkeypatch):
        now = time.time()
        artifacts = tmp_path / "graph_artifacts"
        _make_artifacts(artifacts, "t1", 10, now)

        monkeypatch.setattr(settings, "artifact_retention_days", 30)
        retention.run_retention(artifacts, tmp_path / "osint_cache")
        assert (artifacts / "t1").exists()

        monkeypatch.setattr(settings, "artifact_retention_days", 7)
        report = retention.run_retention(artifacts, tmp_path / "osint_cache")
        assert not (artifacts / "t1").exists()
        assert report.artifact_dirs_removed == 1

    def test_default_is_30_days(self):
        from graph_engine.config import Settings

        assert Settings(_env_file=None).artifact_retention_days == 30
