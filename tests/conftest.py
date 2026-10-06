import os
import pytest
import tempfile
from app.config import settings

@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch, tmp_path):
    # Set up temporary DB and log file for tests
    db_file = tmp_path / "test_sentinel.db"
    log_file = tmp_path / "test_portal_auth.log"
    
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setattr(settings, "LOG_FILE_PATH", str(log_file))
    monkeypatch.setattr(settings, "TRUST_PROXY", True)
    monkeypatch.setattr(settings, "BAN_THRESHOLD", 10)
    monkeypatch.setattr(settings, "WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "BAN_DURATION_SECONDS", 300)
    monkeypatch.setattr(settings, "ADMIN_API_KEY", "test-admin-key")

    from app.db import init_db
    init_db()

    from app.detector import detector
    detector.ip_failures.clear()

    from app.watcher import watcher
    watcher.file_path = str(log_file)
    watcher.last_offset = 0
    watcher.last_inode = None
