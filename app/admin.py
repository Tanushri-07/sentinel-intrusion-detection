import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Header, HTTPException, status, Query, Response
from pydantic import BaseModel, field_validator
from app.config import settings
from app.db import get_db

router = APIRouter(prefix="/v1")

def verify_admin_key(x_api_key: Optional[str] = Header(None, alias="X-Api-Key")):
    if not x_api_key or x_api_key != settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return x_api_key

class ManualDecisionRequest(BaseModel):
    value: str
    duration_seconds: int
    scenario: Optional[str] = "manual"

    @field_validator("value")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError("Invalid IP address")
        return v.strip()

    @field_validator("duration_seconds")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("duration_seconds must be > 0")
        return v

@router.get("/decisions")
def list_decisions(
    ip: Optional[str] = Query(None),
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    with get_db() as conn:
        if ip:
            rows = conn.execute(
                "SELECT * FROM decision WHERE value = ? AND active = 1 ORDER BY id DESC",
                (ip,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM decision WHERE active = 1 ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

@router.post("/decisions", status_code=status.HTTP_201_CREATED)
def create_manual_decision(
    req: ManualDecisionRequest,
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    now_utc = datetime.now(timezone.utc)
    until_dt = now_utc + timedelta(seconds=req.duration_seconds)
    created_at_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_str = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    scenario = req.scenario or "manual"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO decision (scope, value, type, scenario, origin, until, active, created_at, alert_id)
            VALUES ('ip', ?, 'ban', ?, 'admin', ?, 1, ?, NULL)
            """,
            (req.value, scenario, until_str, created_at_str)
        )
        decision_id = cursor.lastrowid
        conn.commit()

        row = conn.execute("SELECT * FROM decision WHERE id = ?", (decision_id,)).fetchone()
        return dict(row)

@router.get("/decisions/check/{ip}")
def check_ip_decision(
    ip: str,
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    now_utc_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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
            (ip, now_utc_str)
        ).fetchone()
        if row:
            return {
                "banned": True,
                "ip": ip,
                "until": row["until"]
            }
        else:
            return {
                "banned": False,
                "ip": ip,
                "until": None
            }

@router.delete("/decisions/{decision_id}")
def delete_decision(
    decision_id: int,
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM decision WHERE id = ?", (decision_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Decision not found")
        conn.commit()
        return {
            "deleted": True,
            "decision_id": decision_id
        }

@router.get("/alerts")
def list_alerts(
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM alert ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

@router.get("/alerts/{alert_id}/explain")
def get_alert_explanation(
    alert_id: int,
    x_api_key: str = Header(None, alias="X-Api-Key")
):
    verify_admin_key(x_api_key)
    with get_db() as conn:
        row = conn.execute("SELECT ai_explanation FROM alert WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        explanation = row["ai_explanation"]
        if not explanation and not settings.AI_API_KEY:
            return {
                "alert_id": alert_id,
                "ai_explanation": None,
                "message": "AI explanation disabled (AI_API_KEY not configured)"
            }
        return {
            "alert_id": alert_id,
            "ai_explanation": explanation
        }
