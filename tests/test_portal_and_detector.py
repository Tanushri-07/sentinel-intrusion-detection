import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.watcher import watcher
from app.db import get_db

@pytest.mark.asyncio
async def test_portal_login_validation_and_logging():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Malformed JSON / missing fields -> 422, no log
        res_422 = await client.post("/login", json={"username": "alice"})
        assert res_422.status_code == 422

        # 2. Username with pipe -> 422, no log
        res_pipe = await client.post("/login", json={"username": "alice|admin", "password": "password123"})
        assert res_pipe.status_code == 422

        # Process watcher -> no new events created
        watcher.read_available()
        with get_db() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
            assert cnt == 0

        # 3. Successful login -> 200, 1 log line
        res_ok = await client.post("/login", json={"username": "alice", "password": "password123"})
        assert res_ok.status_code == 200
        assert res_ok.json() == {"status": "success", "message": "Login successful"}

        watcher.read_available()
        with get_db() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM event WHERE event_type = 'successful_login'").fetchone()[0]
            assert cnt == 1

        # 4. Failed login -> 401, 1 log line
        res_fail = await client.post("/login", json={"username": "alice", "password": "wrong"})
        assert res_fail.status_code == 401

        watcher.read_available()
        with get_db() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM event WHERE event_type = 'failed_login'").fetchone()[0]
            assert cnt == 1
