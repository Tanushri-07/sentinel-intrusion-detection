# Sentinel Intrusion Detection

Sentinel is a lightweight, single-process intrusion detection and prevention system (IPS) designed to protect web applications—such as university student portals during high-traffic result weeks—from automated brute-force password guessing attacks.

Unlike distributed systems like CrowdSec which require separate agent, LAPI, and external bouncer processes with polling latency, Sentinel runs as a unified FastAPI service with an inline **Blocker ASGI middleware** that enforces bans and guarantees **exact, zero-delay ban expiration** at request-time.

---

## Architecture & Core Flow

1. **Client / Attacker** sends HTTP requests (e.g. `POST /login`) towards the **Demo Portal**.
2. **Blocker (Middleware)** intercepts every incoming request before it reaches portal handlers:
   - Resolves client IP (via `X-Forwarded-For` or connection client host).
   - Queries SQLite for an active ban decision where `until > now`.
   - If an active ban exists, immediately aborts and returns `HTTP 403 Forbidden` with the ban expiry timestamp (`until`).
   - If no active ban exists (or `until <= now`), passes the request to the Demo Portal.
3. **Demo Portal** validates credentials against a seeded demo user list (`alice:password123`, `student:secret2024`, `admin:adminpass`).
4. **Structured Logging**: For every login attempt, Demo Portal appends exactly one line to `portal_auth.log`:
   `{timestamp} | ip={ip} | username={username} | result={result}`
5. **Detection Pipeline**:
   - **Log Watcher** tails `portal_auth.log` in real time.
   - **Log Parser** parses raw log lines into structured event objects.
   - **Attack Detector** maintains an in-memory sliding window per IP. When failed attempts reach `BAN_THRESHOLD` within `WINDOW_SECONDS`, it generates an **Alert** and a **Decision** with `until = now + BAN_DURATION_SECONDS` and writes them to SQLite.
6. **Exact Expiry**:
   - Because the Blocker middleware evaluates `until > now` on every incoming request, an IP is unblocked immediately at the exact millisecond the ban expires.
   - A background **Expiry Sweeper** cleans up expired database records for hygiene, but is not required for access to become allowed.
7. **Optional AI Explainer**: When `AI_API_KEY` is set in `.env`, generates human-readable incident summaries for alerts. The system works completely without an AI key.

---

## Prerequisites

- Python 3.11+
- Virtual environment (recommended: `python3 -m venv .venv`)

---

## Quickstart & Demo in 5 Commands

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 2. Install dependencies
pip install fastapi uvicorn pydantic-settings httpx pytest pytest-asyncio

# 3. Configure environment
cp .env.example .env

# 4. Start the Sentinel service
uvicorn app.main:app --port 8000

# 5. Run a Killer Test demo (in a second terminal)
bash scripts/demo_killer_1.sh
```

---

## Running the Test Suite

Run the full automated pytest suite covering all components and Killer Tests:

```bash
pytest -v
```

---

## The Three Killer Tests

Sentinel's reliability and design are verified by three Killer Tests (executable via pytest and manual scripts):

1. **Killer Test 1 — Brute-Force Detection (10 failed logins → Ban)**:
   - When an attacker IP (`198.51.100.10`) sends 10 consecutive failed login attempts within 60 seconds, an Alert and Ban Decision are generated in SQLite.
   - The 11th request is intercepted by Blocker middleware, returning `HTTP 403 Forbidden` with the ban expiration timestamp.
2. **Killer Test 2 — Innocent Bystander Isolation**:
   - An attacker IP (`198.51.100.10`) is banned following 10 failed logins.
   - A legitimate user logging in concurrently or immediately afterward from another IP (`203.0.113.50`) is completely unaffected and successfully logs in (`HTTP 200 OK`).
3. **Killer Test 3 — Exact Expiry**:
   - Configured with a short ban duration (e.g. 2s in tests).
   - Requests are blocked with `HTTP 403` while $t < until$.
   - Immediately at $t > until$, requests are allowed through without delay due to the per-request `until > now` check in middleware, even when the background Expiry Sweeper is disabled.
