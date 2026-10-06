from fastapi import Request
from app.config import settings

def get_client_ip(request: Request) -> str:
    if settings.TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
        if xff:
            first_ip = xff.split(",")[0].strip()
            if first_ip:
                return first_ip
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"
