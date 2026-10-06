import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from app.config import settings
from app.main import app
from app.watcher import watcher

@pytest.mark.asyncio
async def test_killer_3_exact_expiry(monkeypatch):
    attacker_ip = "198.51.100.10"
    # Short ban duration of 2 seconds
    monkeypatch.setattr(settings, "BAN_DURATION_SECONDS", 2)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Trigger ban with 10 failed login attempts
        for i in range(10):
            res = await client.post(
                "/login",
                json={"username": "student", "password": f"wrongpass{i}"},
                headers={"X-Forwarded-For": attacker_ip}
            )
            assert res.status_code == 401
            watcher.read_available()

        # 2. Verify request is blocked immediately while ban is active
        res_blocked = await client.post(
            "/login",
            json={"username": "student", "password": "wrongpass_now"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert res_blocked.status_code == 403
        assert res_blocked.json()["error"] == "IP is banned"

        # 3. Wait 2.1 seconds for exact expiry (without running sweeper)
        await asyncio.sleep(2.1)

        # 4. Next request should immediately pass through (sweeper is NOT needed)
        res_after = await client.post(
            "/login",
            json={"username": "student", "password": "secret2024"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert res_after.status_code == 200
        assert res_after.json()["status"] == "success"
