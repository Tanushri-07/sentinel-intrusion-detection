import os
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, status
from pydantic import BaseModel, field_validator
from app.config import settings
from app.ip_utils import get_client_ip

router = APIRouter()

SEEDED_USERS = {
    "alice": "password123",
    "student": "secret2024",
    "admin": "adminpass"
}

class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if "|" in v:
            raise ValueError("Username cannot contain pipe '|' character")
        return v.strip()

def append_auth_log(ip: str, username: str, result: str):
    # ISO 8601 UTC timestamp format: YYYY-MM-DDTHH:MM:SSZ
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} | ip={ip} | username={username} | result={result}\n"
    log_path = settings.LOG_FILE_PATH
    log_dir = os.path.dirname(log_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()

@router.post("/login")
async def login(req: LoginRequest, request: Request):
    ip = get_client_ip(request)
    
    # Check credentials
    if req.username in SEEDED_USERS and SEEDED_USERS[req.username] == req.password:
        append_auth_log(ip, req.username, "success")
        return {"status": "success", "message": "Login successful"}
    else:
        append_auth_log(ip, req.username, "fail")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"status": "fail", "detail": "Invalid username or password"}
        )
