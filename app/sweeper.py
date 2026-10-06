import asyncio
import logging
from datetime import datetime, timezone
from app.db import get_db

logger = logging.getLogger("sentinel.sweeper")

class ExpirySweeper:
    def __init__(self, interval_seconds: float = 10.0):
        self.interval_seconds = interval_seconds
        self.running = False

    def sweep_once(self):
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE decision 
                    SET active = 0 
                    WHERE active = 1 
                      AND until <= ?
                    """,
                    (now_utc,)
                )
                if cursor.rowcount > 0:
                    logger.info("Sweeper deactivated %d expired decisions", cursor.rowcount)
                conn.commit()
        except Exception as e:
            logger.warning("Error during sweeper run: %s", e)

    async def run(self):
        self.running = True
        while self.running:
            try:
                self.sweep_once()
            except Exception as e:
                logger.warning("Unexpected error in sweeper loop: %s", e)
            await asyncio.sleep(self.interval_seconds)

    def stop(self):
        self.running = False

sweeper = ExpirySweeper()
