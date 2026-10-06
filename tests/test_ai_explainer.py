import pytest
from httpx import AsyncClient, ASGITransport
from app.config import settings
from app.main import app
from app.watcher import watcher
from app.db import get_db

@pytest.mark.asyncio
async def test_ai_explainer_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AI_API_KEY", "")
    attacker_ip = "198.51.100.99"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(10):
            res = await client.post(
                "/login",
                json={"username": "student", "password": f"wrongpass{i}"},
                headers={"X-Forwarded-For": attacker_ip}
            )
            assert res.status_code == 401
            watcher.read_available()

        # Check alert in DB
        with get_db() as conn:
            alert = conn.execute("SELECT * FROM alert WHERE source_ip = ?", (attacker_ip,)).fetchone()
            assert alert is not None
            assert alert["ai_explanation"] is None
            alert_id = alert["id"]

        # Check explain endpoint
        res_explain = await client.get(
            f"/v1/alerts/{alert_id}/explain",
            headers={"X-Api-Key": "test-admin-key"}
        )
        assert res_explain.status_code == 200
        data = res_explain.json()
        assert data["alert_id"] == alert_id
        assert data["ai_explanation"] is None
        assert "disabled" in data.get("message", "")
