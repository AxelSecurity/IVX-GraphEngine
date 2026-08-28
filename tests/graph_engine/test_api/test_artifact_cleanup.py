"""Test per graph_engine.api.artifact_cleanup — pulizia artefatti su disco."""

from __future__ import annotations

from graph_engine.api.artifact_cleanup import remove_artifact_dirs


class TestRemoveArtifactDirs:
    def test_removes_existing_dir(self, tmp_path):
        """La cartella del target eliminato sparisce; le altre restano."""
        art = tmp_path / "artifacts"
        (art / "tid-1" / "s1").mkdir(parents=True)
        (art / "tid-1" / "s1" / "screenshot.png").write_bytes(b"x")
        (art / "tid-2").mkdir(parents=True)

        remove_artifact_dirs(["tid-1"], artifact_root=art)

        assert not (art / "tid-1").exists()
        assert (art / "tid-2").exists()

    def test_missing_dir_is_not_an_error(self, tmp_path):
        """Cartella assente (capture_artifacts=False) → nessun errore."""
        art = tmp_path / "artifacts"
        art.mkdir()
        # Nessuna cartella per "ghost"

        remove_artifact_dirs(["ghost"], artifact_root=art)  # non deve sollevare

        assert (art).is_dir()

    def test_path_traversal_never_escapes_artifact_root(self, tmp_path):
        """Un target_id malizioso non può cancellare fuori da artifact_root."""
        art = tmp_path / "artifacts"
        art.mkdir()
        outside = tmp_path / "prezioso"
        outside.mkdir()
        (outside / "dato.txt").write_text("non toccare")

        remove_artifact_dirs(["../../prezioso"], artifact_root=art)

        assert outside.is_dir()
        assert (outside / "dato.txt").exists()
