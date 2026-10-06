import asyncio
import os
import logging
from typing import Optional
from app.config import settings
from app.detector import detector

logger = logging.getLogger("sentinel.watcher")

class LogWatcher:
    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path or settings.LOG_FILE_PATH
        self.last_offset = 0
        self.last_inode = None
        self.running = False

    def parse_line(self, line: str):
        line = line.strip()
        if not line:
            return
        # Expected format: {timestamp} | ip={ip} | username={username} | result=success|fail
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 4:
            logger.warning("Discarding malformed log line (part count != 4): %s", line)
            return

        ts, ip_part, user_part, res_part = parts
        if not (ip_part.startswith("ip=") and user_part.startswith("username=") and res_part.startswith("result=")):
            logger.warning("Discarding malformed log line (field prefix mismatch): %s", line)
            return

        ip = ip_part[3:].strip()
        username = user_part[9:].strip()
        result = res_part[7:].strip()

        if result not in ("success", "fail"):
            logger.warning("Discarding malformed log line (invalid result '%s'): %s", result, line)
            return

        event_type = "successful_login" if result == "success" else "failed_login"
        detector.process_event(
            timestamp=ts,
            source_ip=ip,
            event_type=event_type,
            username=username,
            raw_line=line
        )

    def read_available(self):
        if not os.path.exists(self.file_path):
            return

        try:
            stat = os.stat(self.file_path)
            current_inode = (stat.st_ino, stat.st_dev)
            current_size = stat.st_size

            # Inode changed (file rotation / replacement)
            if self.last_inode is not None and current_inode != self.last_inode:
                self.last_offset = 0

            # File truncated
            if current_size < self.last_offset:
                self.last_offset = 0

            self.last_inode = current_inode

            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.last_offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    # If line doesn't end with newline, we might have read a partial line
                    if not line.endswith("\n"):
                        # Rewind back
                        f.seek(self.last_offset)
                        break
                    self.last_offset = f.tell()
                    self.parse_line(line)
        except Exception as e:
            logger.warning("Error reading log file: %s", e)

    async def run(self):
        self.running = True
        # Ensure log file exists at startup
        log_dir = os.path.dirname(self.file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        if not os.path.exists(self.file_path):
            with open(self.file_path, "a", encoding="utf-8") as f:
                pass

        while self.running:
            try:
                self.read_available()
            except Exception as e:
                logger.warning("Unexpected error in watcher loop: %s", e)
            await asyncio.sleep(0.1)

    def stop(self):
        self.running = False

watcher = LogWatcher()
