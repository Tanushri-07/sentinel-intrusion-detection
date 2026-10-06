import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db import get_db

@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json() == {"status": "ok", "service": "sentinel"}

@pytest.mark.asyncio
async def test_admin_auth_failures():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Missing header
        res1 = await client.get("/v1/decisions")
        assert res1.status_code == 401
        assert res1.json() == {"detail": "Invalid or missing API key"}

        # Wrong header
        res2 = await client.get("/v1/decisions", headers={"X-Api-Key": "wrong-key"})
        assert res2.status_code == 401
        assert res2.json() == {"detail": "Invalid or missing API key"}

@pytest.mark.asyncio
async def test_manual_decision_crud():
    transport = ASGITransport(app=app)
    headers = {"X-Api-Key": "test-admin-key"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Invalid IP
        res_bad_ip = await client.post(
            "/v1/decisions",
            json={"value": "not-an-ip", "duration_seconds": 60},
            headers=headers
        )
        assert res_bad_ip.status_code == 422

        # 2. Invalid duration
        res_bad_dur = await client.post(
            "/v1/decisions",
            json={"value": "192.0.2.1", "duration_seconds": -10},
            headers=headers
        )
        assert res_bad_dur.status_code == 422

        # 3. Create valid manual decision
        res_create = await client.post(
            "/v1/decisions",
            json={"value": "192.0.2.1", "duration_seconds": 3600, "scenario": "manual_ban"},
            headers=headers
        )
        assert res_create.status_code == 201
        dec = res_create.json()
        dec_id = dec["id"]
        assert dec["value"] == "192.0.2.1"
        assert dec["scenario"] == "manual_ban"

        # 4. Check status
        res_check = await client.get("/v1/decisions/check/192.0.2.1", headers=headers)
        assert res_check.status_code == 200
        assert res_check.json()["banned"] is True

        # 5. List decisions
        res_list = await client.get("/v1/decisions", headers=headers)
        assert res_list.status_code == 200
        assert len(res_list.json()) >= 1

        # 6. Delete decision
        res_del = await client.delete(f"/v1/decisions/{dec_id}", headers=headers)
        assert res_del.status_code == 200
        assert res_del.json() == {"deleted": True, "decision_id": dec_id}

        # Check status again
        res_check2 = await client.get("/v1/decisions/check/192.0.2.1", headers=headers)
        assert res_check2.status_code == 200
        assert res_check2.json()["banned"] is False
