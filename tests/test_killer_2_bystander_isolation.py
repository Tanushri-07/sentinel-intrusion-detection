import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.watcher import watcher

@pytest.mark.asyncio
async def test_killer_2_bystander_isolation():
    attacker_ip = "198.51.100.10"
    innocent_ip = "203.0.113.50"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Attacker generates 10 failed login attempts
        for i in range(10):
            res = await client.post(
                "/login",
                json={"username": "student", "password": f"wrongpass{i}"},
                headers={"X-Forwarded-For": attacker_ip}
            )
            assert res.status_code == 401
            watcher.read_available()

        # Attacker is now banned
        res_attacker = await client.post(
            "/login",
            json={"username": "student", "password": "wrongpass_again"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert res_attacker.status_code == 403
        assert res_attacker.json()["error"] == "IP is banned"

        # 2. Legitimate user logs in with valid credentials from different IP
        res_innocent = await client.post(
            "/login",
            json={"username": "student", "password": "secret2024"},
            headers={"X-Forwarded-For": innocent_ip}
        )
        assert res_innocent.status_code == 200
        assert res_innocent.json()["status"] == "success"

        # 3. Verify attacker remains blocked
        res_attacker_2 = await client.post(
            "/login",
            json={"username": "student", "password": "secret2024"},
            headers={"X-Forwarded-For": attacker_ip}
        )
        assert res_attacker_2.status_code == 403
