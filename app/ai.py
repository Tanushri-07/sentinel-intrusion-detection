import asyncio
import logging
import httpx
from app.config import settings
from app.db import get_db

logger = logging.getLogger("sentinel.ai")

async def explain_alert_task(alert_id: int, source_ip: str, scenario: str, event_count: int, window_seconds: int, stopped_at: str):
    if not settings.AI_API_KEY:
        logger.info("AI explanation disabled (AI_API_KEY not configured)")
        return

    prompt = (
        f"You are a cybersecurity expert. Explain in 1-2 concise sentences why the following security event is suspicious:\n"
        f"Scenario: {scenario}\n"
        f"Source IP: {source_ip}\n"
        f"Failed login attempts: {event_count} in {window_seconds} seconds\n"
        f"Timestamp: {stopped_at}\n"
        f"Do not include markdown or formatting, just provide the 1-2 sentence threat explanation."
    )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.AI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2
                }
            )
            if response.status_code == 200:
                data = response.json()
                explanation = data["choices"][0]["message"]["content"].strip()
                with get_db() as conn:
                    conn.execute(
                        "UPDATE alert SET ai_explanation = ? WHERE id = ?",
                        (explanation, alert_id)
                    )
                    conn.commit()
            else:
                logger.warning("Groq API returned status %d: %s", response.status_code, response.text)
    except Exception as e:
        logger.warning("Failed to generate AI explanation for alert %d: %s", alert_id, e)
