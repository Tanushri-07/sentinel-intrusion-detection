# Architecture — Sentinel Intrusion Detection

---

## Overview

Sentinel is a single-process intrusion detection and prevention system designed for the university portal. Unlike CrowdSec's distributed Agent + LAPI architecture, Sentinel is a monolithic application where the demo portal, blocker middleware, log watcher, parser, detector, decision store, and admin API all run within a single process. This simplifies deployment and guarantees zero-delay, synchronous ban enforcement and exact expiry.

---

## Locked Technology Stack

- **Runtime & Language**: Python 3.11+
- **Web Framework**: FastAPI (running on Uvicorn ASGI server as a single worker process)
- **Database**: Local disk-backed SQLite database using Python standard-library `sqlite3` module (WAL journal mode enabled). Third-party ORMs or async SQLite drivers (SQLAlchemy, aiosqlite, Tortoise) are explicitly excluded.
- **Production Dependencies**:
  - `fastapi`
  - `uvicorn[standard]`
  - `pydantic`
  - `pydantic-settings`
  - `httpx`
- **Testing Dependencies**:
  - `pytest`
  - `pytest-asyncio`
- **No Extra Infrastructure**: Celery, Redis, RabbitMQ, external database servers, or distributed message queues are strictly forbidden.

---

## Components

| Component | Responsibility |
|---|---|
| **Demo Portal** | FastAPI application hosting simulated university portal endpoints, including `POST /login`. Validates credentials against a seeded demo user list and writes a structured auth log line per attempt to `portal_auth.log`. |
| **Blocker (Middleware)** | FastAPI / ASGI middleware positioned in front of the Demo Portal and other protected routes. On every request, determines client IP, checks SQLite for an active decision (`until > now`), and returns `HTTP 403 Forbidden` with the ban expiry timestamp if banned. |
| **Log Watcher** | Polling background task (100 ms interval) that tails `portal_auth.log`, tracks file offset and inode replacement, and emits raw lines into the parser queue. |
| **Log Parser** | Transforms raw log lines into structured events (`timestamp`, `source_ip`, `username`, `result`). Discards malformed lines with warnings. |
| **Attack Detector** | Maintains ephemeral in-memory per-IP sliding deques of failed login timestamps. Evaluates `BAN_THRESHOLD` failed logins within `WINDOW_SECONDS`. On breach, creates exactly one Alert and one Decision, and immediately clears that IP's deque. |
| **Decision Store** | SQLite database tables (`event`, `alert`, `decision`) storing active and past decisions with exact expiration timestamps, queried synchronously via Python's standard-library `sqlite3`. |
| **Admin API** | REST endpoints (`/v1/decisions`, `/v1/alerts`, `/health`, etc.) protected by `X-Api-Key: <ADMIN_API_KEY>` (returning `401 Unauthorized` if invalid) for administrators to monitor alerts, query active bans, manually ban IPs (`POST /v1/decisions`), and unban IPs. |
| **Expiry Sweeper** | Periodic background cleanup task that marks past decisions (`until <= now`) as inactive (`active = 0`) for database hygiene. **Does not control enforcement**; request-time middleware check guarantees exact expiry. |
| **AI Threat Explainer** | Optional asynchronous background task calling Groq's OpenAI-compatible API (`llama-3.1-8b-instant`) to generate human-readable explanations for created alerts when `AI_API_KEY` is present. Never blocks ban creation or enforcement. |

---

## Demo Portal Specification

The Demo Portal simulates the target web application (e.g. university result portal):
- **Endpoint**: `POST /login`
- **Request Payload**: JSON with `username` and `password`:
  ```json
  {
    "username": "student",
    "password": "secret2024"
  }
  ```
- **FastAPI Schema Validation & Logging Rules**:
  - If JSON is malformed, required fields (`username`, `password`) are missing, or fields fail schema validation, FastAPI immediately returns `HTTP 422 Unprocessable Entity`.
  - In this case (`HTTP 422`), **DO NOT append any line to `portal_auth.log`** because the login handler was never entered.
  - Usernames containing the pipe character `|` are rejected as invalid during login validation so that log delimiters remain strictly unambiguous.
  - Passwords are NEVER logged (plaintext passwords must not appear in logs or databases).
- **Seeded User List**: Credential validation checks against a hardcoded in-memory seeded dictionary:
  - `alice:password123`
  - `student:secret2024`
  - `admin:adminpass`
- **Response**:
  - `200 OK` with `{"status": "success", "message": "Login successful"}` if credentials match.
  - `401 Unauthorized` with `{"status": "fail", "detail": "Invalid username or password"}` if credentials do not match.
- **Structured Log Output**: Every login request passing schema validation (both success and fail) MUST append exactly one line to `portal_auth.log` (`LOG_FILE_PATH`) with a single append operation followed by a newline.

### Exact Log Line Format

```
{timestamp} | ip={ip} | username={username} | result=success|fail
```

**Field Specifications**:
- **`timestamp`**: ISO 8601 formatted UTC timestamp with timezone indicator: `YYYY-MM-DDTHH:MM:SSZ` (e.g. `2026-10-05T22:30:00Z`).
- **`ip`**: Client IP address determined according to the Client IP Resolution rules below.
- **`username`**: Submitted username (stripped of leading/trailing whitespace, or `anonymous` if omitted).
- **`result`**: Exact literal string `success` (for valid credentials) or `fail` (for invalid credentials).
- **Delimiter**: Space-pipe-space (` | `).

Example log lines:
```
2026-10-05T22:30:00Z | ip=198.51.100.10 | username=student | result=fail
2026-10-05T22:30:05Z | ip=198.51.100.10 | username=student | result=success
```


---

## Log Watcher & Parser Specification

1. **Process & Concurrency Model**:
   - The application runs as a **single Uvicorn worker process** for all operations. Concurrent multi-process file writing is explicitly out of scope.
   - The portal writes each complete log line with a single atomic append operation (`open(..., 'a').write(line + '\n')`).
2. **File Initialization**:
   - `portal_auth.log` (`LOG_FILE_PATH`) is automatically created during application startup if it does not already exist.
3. **Polling Mechanism**:
   - The Log Watcher runs as an `asyncio` background task using simple polling (polling interval: **100 ms**) rather than OS-specific filesystem notifications (`inotify`/`watchdog`).
   - The watcher tracks its current file byte offset across polling iterations.
   - **File Truncation**: If the file size becomes smaller than the tracked offset, the file was truncated/cleared; the watcher resets its offset to zero.
   - **File Rotation / Replacement**: If the file's inode or file identity changes, the watcher detects the change, closes the old handle, opens the new file, and starts reading from byte offset zero.
4. **Parsing & Malformed Line Handling**:
   - The parser verifies that lines strictly follow `{timestamp} | ip={ip} | username={username} | result=success|fail`.
   - If a line is malformed (e.g. invalid timestamp format, missing delimiters, extra tokens, invalid result token), the line is **discarded and a warning is emitted**.
   - Malformed lines NEVER crash or stop the watcher task. Valid lines are transformed into structured events and passed to the detector queue.

---

## Attack Detector State & Reset Semantics

1. **In-Memory Ephemeral State**:
   - The detector maintains an in-memory `collections.deque` of failed-login timestamps partitioned by client IP.
   - The detector state is **ephemeral**: it is NOT reconstructed from SQLite after application restart.
   - SQLite `alert` and `decision` records remain durable across restarts.
   - After restart, detection begins a fresh in-memory sliding window evaluated against newly observed log events.
2. **Threshold Evaluation & Deque Clearing**:
   - On each failed login event, timestamps older than `(current_event_time - WINDOW_SECONDS)` are pruned from the IP's deque, and the new failure timestamp is appended.
   - When the count of failures in the deque reaches `BAN_THRESHOLD` (e.g. 10 failures):
     1. Create **exactly one Alert** in SQLite for that threshold event.
     2. Create **exactly one ban Decision** in SQLite with `until = now + BAN_DURATION_SECONDS`.
     3. **Immediately clear that IP's deque** (`deque.clear()`).
3. **Subsequent Attempts During Active Ban**:
   - Failed attempts occurring from an IP while an active ban already exists in SQLite do NOT extend the existing ban and do NOT create additional alerts.
   - Subsequent requests from that IP are blocked at request-time by the Blocker middleware with `HTTP 403 Forbidden` and do not reach the login handler while the ban is active.

---

## AI Threat Explainer Specification (Optional)

1. **Strict Asynchronous Execution**:
   - The AI Threat Explainer runs **only after** an Alert and Ban Decision are successfully committed to SQLite.
   - It runs asynchronously as a background task (`asyncio.create_task`).
   - It **NEVER blocks** ban creation, Alert creation, or Blocker enforcement.
2. **Provider & Configuration**:
   - **Provider**: Groq OpenAI-compatible chat-completions HTTP API (`https://api.groq.com/openai/v1/chat/completions`).
   - **Model**: `llama-3.1-8b-instant`.
   - **Authentication**: Sent via `Authorization: Bearer <AI_API_KEY>`.
   - **Timeout**: Strict **5.0-second HTTP timeout**.
   - **Retries**: Zero retries (no retries).
3. **Context & Non-Secret Payload**:
   - The AI task receives only non-secret alert context: Alert ID, source IP, scenario name, failure count, sliding window duration, and incident timestamp.
   - No credentials, passwords, or internal application secrets are ever included.
   - Never store or expose `AI_API_KEY` in logs or database tables.
4. **Fallback & Failure Handling**:
   - If `AI_API_KEY` is empty or omitted in `.env`, the background task is skipped, an informational notice is logged, and `alert.ai_explanation` remains `NULL`.
   - If the HTTP request fails, times out, or returns a non-200 code, `alert.ai_explanation` remains `NULL`.
   - Any AI failure is caught and logged; it MUST NEVER cause alert creation, ban decision creation, or enforcement to fail.
5. **Output**:
   - On success, the model returns a concise 1–2 sentence human-readable explanation of why the activity was suspicious, which is updated into `alert.ai_explanation` in SQLite.
---

## Blocker Middleware Specification & Exact Expiry

The Blocker is implemented as ASGI middleware running on every HTTP request entering the application:

1. **Client IP Extraction**: On each incoming request, extract the client IP:
   - By default (`TRUST_PROXY=false`), inspect the ASGI connection socket address (`request.client.host`).
   - Only when `TRUST_PROXY=true` in `.env`, inspect the `X-Forwarded-For` header (taking the leftmost / first client IP).
2. **Active Decision Check**: Query the SQLite database:
   ```sql
   SELECT until FROM decision 
   WHERE value = :client_ip 
     AND type = 'ban' 
     AND until > :current_timestamp 
   ORDER BY until DESC LIMIT 1;
   ```
3. **Enforcement**:
   - If an active ban is found (`until > now`): Immediately halt request processing and return `HTTP 403 Forbidden` with a JSON payload containing the ban end time:
     ```json
     {
       "error": "IP is banned",
       "ip": "198.51.100.10",
       "until": "2026-10-05T22:35:00Z"
     }
     ```
   - If no active ban is found (`until <= now` or no record exists): Forward the request down the middleware chain to the Demo Portal or API handler.

### Request-Time Expiry vs. Sweeper Cleanup

A critical architectural distinction in Sentinel:
- **Request-Time Expiry Check Controls Enforcement**: Because the Blocker middleware evaluates `until > now` dynamically on every incoming request, an IP is unblocked **at the exact millisecond** the ban expires. Zero delay, zero polling latency, and no dependency on background task execution.
- **The Expiry Sweeper Only Performs Cleanup**: The background Expiry Sweeper runs periodically (e.g., every 10–30 seconds) and executes:
  ```sql
  UPDATE decision SET active = 0 WHERE active = 1 AND until <= :current_timestamp;
  ```
  The sweeper's sole purpose is database hygiene and keeping `active = 1` indexed queries compact. Even if the sweeper process stops or stalls, requests will never be blocked after `until`.

---

## Configuration (.env)

All runtime parameters are configured via environment variables (loaded via `pydantic-settings` or `python-dotenv`):

| Variable | Default Value | Description |
|---|---|---|
| `BAN_THRESHOLD` | `10` | Number of failed login attempts required to trigger an automatic ban. |
| `WINDOW_SECONDS` | `60` | Sliding time window in seconds during which failed logins are counted. |
| `BAN_DURATION_SECONDS` | `300` | Duration of the ban in seconds (default 5 minutes; short values e.g. 2s used in tests). |
| `LOG_FILE_PATH` | `portal_auth.log` | File path where the Demo Portal writes auth logs and Log Watcher tails. |
| `DATABASE_URL` | `sqlite:///./sentinel.db` | SQLite database connection string or file path. |
| `ADMIN_API_KEY` | `sentinel-admin-secret-key` | Secret key required for `/v1/*` admin management endpoints (`X-Api-Key` header). Loaded from environment; never hardcoded. |
| `AI_API_KEY` | `""` | Optional external LLM API key. If empty or absent, AI explanation is disabled gracefully. |
| `TRUST_PROXY` | `false` | Boolean (`true`/`false`). When `false`, uses connection socket IP; when `true`, parses `X-Forwarded-For`. |

---

## Single-Laptop Multi-IP Architecture (TRUST_PROXY)

To allow comprehensive testing and interactive demonstrations of multi-IP scenarios (such as Killer Test 2 innocent bystander isolation) from a single developer machine:
- **Server Configuration**: The demo scripts start the Sentinel service with `TRUST_PROXY=true` in the environment.
- **Client Requests**: Each `curl` invocation supplies an explicit `X-Forwarded-For` header:
  - Attacker requests send `-H "X-Forwarded-For: 198.51.100.10"`.
  - Normal / innocent user requests send `-H "X-Forwarded-For: 203.0.113.50"`.
- **Resolution**: With `TRUST_PROXY=true`, the Blocker middleware and Demo Portal resolve the client IP from the `X-Forwarded-For` header instead of the local socket loopback (`127.0.0.1`), demonstrating true multi-IP defense on a single laptop.

---

## Mermaid Architecture Diagram

```mermaid
flowchart TD
    Client[Client / Attacker] -->|HTTP Request| Blocker[Blocker ASGI Middleware]
    
    subgraph Blocker Enforcement
        Blocker -->|1. Extract IP: socket or XFF if TRUST_PROXY| Blocker
        Blocker -->|2. Check until > now| DS[(SQLite Database)]
        DS -->|Ban active: until > now| Blocker
        Blocker -->|3. If banned: 403 Forbidden with until| Client
    end

    Blocker -->|4. If not banned: allow| Portal[Demo Portal: POST /login]
    Portal -->|5. Validate vs seeded users| Portal
    Portal -->|6. Append log line| LogFile[portal_auth.log]
    
    subgraph Detection Pipeline
        LogFile -->|Tail file| Watcher[Log Watcher]
        Watcher -->|Raw line channel| Parser[Log Parser]
        Parser -->|Structured event channel| Detector[Attack Detector]
        Detector -->|Sliding window count >= BAN_THRESHOLD| AlertGen[Alert & Decision Generator]
        AlertGen -->|Write Alert & Decision: until = now + BAN_DURATION| DS
        AlertGen -.->|If AI_API_KEY configured| AI[AI Threat Explainer]
        AI -.->|Attach explanation| DS
    end

    subgraph Background Hygiene
        Sweeper[Expiry Sweeper Background Task] -->|Periodic cleanup: active = 0 where until <= now| DS
    end

    subgraph Administration
        Admin[Administrator] -->|HTTP with X-Api-Key| AdminAPI[Admin API /v1/...]
        AdminAPI -->|Query/Delete/Create decisions & alerts| DS
    end

    style AI stroke-dasharray: 5 5
```

---

## How the Three Killer Tests Are Supported

### Killer Test 1 (10 failed logins → Ban)
- Attack Detector maintains in-memory sliding window of failed attempts per IP.
- When 10 failed login events occur within 60 seconds (`WINDOW_SECONDS`), a ban decision is written to SQLite with `until = now + BAN_DURATION_SECONDS`.
- The very next request from that IP is intercepted by Blocker middleware, returning `HTTP 403 Forbidden` with `until`.

### Killer Test 2 (Innocent bystander isolation)
- Sliding windows and SQLite decision records are strictly partitioned by IP (`value = client_ip`).
- Demo scripts run the server with `TRUST_PROXY=true` and pass `X-Forwarded-For: 198.51.100.10` for the attacker and `X-Forwarded-For: 203.0.113.50` for the normal user.
- Only the attacking IP (`198.51.100.10`) has decision records created.
- Legitimate traffic from `203.0.113.50` finds no matching record in SQLite and receives `HTTP 200 OK` from the Demo Portal, completely isolated from the ban on the same machine.

### Killer Test 3 (Exact expiry)
- Ban is created with short duration (e.g., 2 seconds).
- While $t < until$, requests from the IP receive `HTTP 403`.
- The moment $t \ge until$, the middleware SQL check `WHERE value = ? AND until > :now` yields 0 results. The request immediately passes through with `HTTP 200 OK`.
- Expiry is exact to the millisecond without relying on the background sweeper.
