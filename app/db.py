import sqlite3
import os
from contextlib import contextmanager
from typing import Generator
from app.config import settings

def get_db_path() -> str:
    url = settings.DATABASE_URL
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "", 1)
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "", 1)
    return url

def get_db_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    # Ensure directory exists if path contains directories
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. ALERT table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            stopped_at TEXT NOT NULL,
            message TEXT,
            ai_explanation TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_source_ip ON alert(source_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_created_at ON alert(created_at);")

        # 2. EVENT table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            raw_line TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            alert_id INTEGER,
            FOREIGN KEY (alert_id) REFERENCES alert(id) ON DELETE SET NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_ip_time ON event(source_ip, timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_alert_id ON event(alert_id);")

        # 3. DECISION table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS decision (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL DEFAULT 'ip',
            value TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'ban',
            scenario TEXT NOT NULL,
            origin TEXT NOT NULL DEFAULT 'sentinel',
            until TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            alert_id INTEGER,
            FOREIGN KEY (alert_id) REFERENCES alert(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_decision_enforce ON decision(value, until);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_decision_active_until ON decision(active, until);")
        
        conn.commit()
