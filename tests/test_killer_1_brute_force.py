import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.watcher import watcher
from app.db import get_db

@pytest.mark.asyncio
async def test_killer_1_brute_force():
    attacker_ip = "198.51.100.10"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Send 10 failed login attempts
        for i in range(10):
            res = await client.post(
                "/login",
                json={"username": "student", "password": f"wrongpass{i}"},
                headers={"X-Forwarded-For": attacker_ip}
            )
            assert res.status_code == 401
            # Process log line synchronously
            watcher.read_available()

        # Check that alert and decision are created in SQLite
        with get_db() as conn:
            alert = conn.execute("SELECT * FROM alert WHERE source_ip = ?", (attacker_ip,)).fetchone()
            assert alert is not None
            assert alert["event_count"] == 10

            decision = conn.execute("SELECT * FROM decision WHERE value = ? AND active = 1", (attacker_ip,)).fetchone()
            assert decision is not None
            assert decision["type"] == "ban"

        # 11th request from attacker must be blocked with 403 Forbidden
        res11 = await client.post(
            "/login",
            json={"username": "student", "password": "anypassword"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert res11.status_code == 403
        data = res11.json()
        assert data["error"] == "IP is banned"
        assert data["ip"] == attacker_ip
        assert "until" in data
