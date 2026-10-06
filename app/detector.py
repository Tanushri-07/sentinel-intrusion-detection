import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict
from app.config import settings
from app.db import get_db
from app.ai import explain_alert_task

logger = logging.getLogger("sentinel.detector")

class AttackDetector:
    def __init__(self):
        # Maps IP string -> deque of datetime timestamps (UTC)
        self.ip_failures: Dict[str, deque] = defaultdict(deque)

    def is_ip_currently_banned(self, ip: str, now_utc_str: str) -> bool:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id FROM decision WHERE value = ? AND type = 'ban' AND until > ? LIMIT 1",
                (ip, now_utc_str)
            ).fetchone()
            return row is not None

    def process_event(self, timestamp: str, source_ip: str, event_type: str, username: str, raw_line: str):
        # 1. Store event in SQLite
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO event (timestamp, source_ip, event_type, username, raw_line)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, source_ip, event_type, username, raw_line)
            )
            event_id = cursor.lastrowid
            conn.commit()

        if event_type != "failed_login":
            return

        # Parse event timestamp
        try:
            # Parse ISO 8601 string, e.g., 2026-10-05T22:30:00Z
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except Exception:
            dt = datetime.now(timezone.utc)

        now_utc = datetime.now(timezone.utc)
        now_utc_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Check if IP has an active ban already
        if self.is_ip_currently_banned(source_ip, now_utc_str):
            logger.info("IP %s already banned; ignoring new failure for alert/ban creation", source_ip)
            return

        # Update sliding window deque
        cutoff = dt - timedelta(seconds=settings.WINDOW_SECONDS)
        q = self.ip_failures[source_ip]
        while q and q[0] < cutoff:
            q.popleft()

        q.append(dt)

        if len(q) >= settings.BAN_THRESHOLD:
            started_at = q[0].strftime("%Y-%m-%dT%H:%M:%SZ")
            stopped_at = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            event_count = len(q)
            scenario = "brute_force_login"
            message = f"{event_count} failed logins in {settings.WINDOW_SECONDS} seconds"

            # Calculate until timestamp for decision
            until_dt = now_utc + timedelta(seconds=settings.BAN_DURATION_SECONDS)
            until_str = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            created_at_str = now_utc_str

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO alert (scenario, source_ip, event_count, started_at, stopped_at, message, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scenario, source_ip, event_count, started_at, stopped_at, message, created_at_str)
                )
                alert_id = cursor.lastrowid

                # Link recent events to this alert
                cursor.execute(
                    """
                    UPDATE event SET alert_id = ? WHERE source_ip = ? AND alert_id IS NULL AND event_type = 'failed_login'
                    """,
                    (alert_id, source_ip)
                )

                # Create Decision
                cursor.execute(
                    """
                    INSERT INTO decision (scope, value, type, scenario, origin, until, active, created_at, alert_id)
                    VALUES ('ip', ?, 'ban', ?, 'sentinel', ?, 1, ?, ?)
                    """,
                    (source_ip, scenario, until_str, created_at_str, alert_id)
                )
                conn.commit()

            # Clear that IP's deque
            q.clear()
            logger.info("Ban created for IP %s until %s (Alert #%d)", source_ip, until_str, alert_id)

            # Trigger optional AI explainer
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(explain_alert_task(
                    alert_id=alert_id,
                    source_ip=source_ip,
                    scenario=scenario,
                    event_count=event_count,
                    window_seconds=settings.WINDOW_SECONDS,
                    stopped_at=stopped_at
                ))
            except RuntimeError:
                pass

detector = AttackDetector()
