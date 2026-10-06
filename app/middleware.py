from datetime import datetime, timezone
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.db import get_db
from app.ip_utils import get_client_ip

class BlockerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Health check is always public and bypassed
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = get_client_ip(request)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Check SQLite synchronously for active ban
        is_banned = False
        ban_until = None
        with get_db() as conn:
            row = conn.execute(
                """
                SELECT until FROM decision 
                WHERE value = ? 
                  AND type = 'ban' 
                  AND until > ?
                ORDER BY until DESC 
                LIMIT 1
                """,
                (client_ip, now_utc)
            ).fetchone()
            if row:
                is_banned = True
                ban_until = row["until"]

        if is_banned:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "IP is banned",
                    "ip": client_ip,
                    "until": ban_until
                }
            )

        return await call_next(request)
