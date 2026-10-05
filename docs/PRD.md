# Product Requirements Document — Sentinel Intrusion Detection

---

## 1. Problem

During result week, the university portal is overwhelmed by bots guessing student passwords. These brute-force attacks degrade service for legitimate students trying to access their results. The university needs a reliable, lightweight system to detect and block attacking IPs in real time with exact ban expiration.

---

## 2. Target User

University IT administrators responsible for keeping the student result portal available, secure, and responsive during high-traffic periods.

---

## 3. Problem Statement

"For university IT administrators who struggle with bot-driven brute-force attacks during result week, Sentinel Intrusion Detection automatically reads server logs, detects attack patterns, and bans attacking IPs with precise automatic expiry, unlike CrowdSec which relies on query-time-only polling with no proactive unblock notification and offers no AI-powered threat explanation."

---

## 4. Technology Stack (Locked)

- **Language / Runtime**: Python 3.11+
- **API Framework**: FastAPI (running on Uvicorn ASGI server as a single worker process)
- **Database**: Local disk-backed SQLite using Python standard library `sqlite3` (WAL mode enabled)
- **Production Dependencies**: `fastapi`, `uvicorn[standard]`, `pydantic`, `pydantic-settings`, `httpx`
- **Test Dependencies**: `pytest`, `pytest-asyncio`
- **External Infrastructure**: None (no Redis, Celery, RabbitMQ, or external DBs)

---

## 5. Core Flow

1. The university portal (**Demo Portal**) receives authentication attempts (`POST /login`) and writes structured log lines to `portal_auth.log`.
2. Sentinel's **Log Watcher** tails the log file and emits raw log lines into an in-memory queue/channel.
3. The **Log Parser** transforms each raw line into a structured event (`timestamp`, `ip`, `username`, `result`).
4. The **Attack Detector** receives parsed events and maintains ephemeral in-memory per-IP sliding deques of failed login timestamps. It evaluates configured scenarios (`BAN_THRESHOLD` failed logins within `WINDOW_SECONDS`).
5. When the threshold is reached within the window:
   - Exactly one **Alert** is created in SQLite.
   - Exactly one ban **Decision** is created in SQLite with `until = now + BAN_DURATION_SECONDS`.
   - The IP's in-memory deque is immediately cleared.
   - Subsequent failed attempts during an active ban do not extend the ban or create duplicate alerts.
   - An asynchronous background task optionally queries Groq's API (`llama-3.1-8b-instant`) to generate `ai_explanation` without blocking ban enforcement.
6. The **Blocker** middleware intercepts incoming requests to the portal. It checks SQLite for an active decision where `until > now`. If active, it immediately returns `HTTP 403 Forbidden` with the ban expiry timestamp.
7. The moment `now >= until`, the request passes through cleanly. The **Expiry Sweeper** cleans up stale database records in the background.

---

## 6. Scope Boundaries

### Must Have
- **M1**: Demo Portal with `POST /login` validating seeded credentials and writing structured logs to `portal_auth.log`.
- **M2**: ASGI Blocker middleware checking `until > now` on every request and returning HTTP 403 with `until`.
- **M3**: Tail-based log watcher and parser for `portal_auth.log`.
- **M4**: Sliding-window brute force detector (configurable `BAN_THRESHOLD` and `WINDOW_SECONDS`).
- **M5**: Decision storage in SQLite with exact `until` timestamp.
- **M6**: Expiry sweeper cleaning up expired decisions.
- **M7**: Configurable client IP resolution (`TRUST_PROXY` support).
- **M8**: Admin REST API to query alerts and active bans.
- **M9**: Optional AI Explainer generating threat explanations when `AI_API_KEY` is present.

### Out of Scope
- Modifying third-party university portal legacy code.
- Replacing external web servers (Nginx/Apache) or load balancers.
- GeoIP ASN enrichment.
- CrowdSec CAPI community threat intelligence sharing.

---

## 7. Acceptance Criteria & Killer Test Execution

The system's correctness is validated through three Killer Tests. Each test is specified in **Given / When / Then** format, followed by both automated `pytest` and manual demo script execution details.

> [!NOTE]
> **Single-Laptop Multi-IP Demonstration**: For manual demo scripts, the server must be started with `TRUST_PROXY=true` in `.env` (or environment), and each `curl` command sends a distinct `X-Forwarded-For` header (e.g., attacker `198.51.100.10`, normal user `203.0.113.50`). This allows realistic multi-IP traffic to be tested and demonstrated from a single developer machine.

---

### Killer Test 1 — Brute-Force Detection

**Given** an attacker IP (`198.51.100.10`) generates failed login attempts against `POST /login`,  
**When** the 10th failed login attempt occurs within 60 seconds (`BAN_THRESHOLD=10`, `WINDOW_SECONDS=60`),  
**Then** an Alert and Ban Decision (`until = now + BAN_DURATION_SECONDS`) are recorded in SQLite, and all subsequent requests from that IP are blocked by Blocker middleware returning `HTTP 403 Forbidden` with the ban expiry timestamp (`until`).

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_1_brute_force.py`
  - How it runs: Initializes a test SQLite database and mounts Blocker middleware and Demo Portal with `TRUST_PROXY=true`. Sends 10 invalid `POST /login` requests with `X-Forwarded-For: 198.51.100.10`, processes log events through the pipeline, and asserts the 11th request returns `HTTP 403 Forbidden` with body `{"error": "IP is banned", "ip": "198.51.100.10", "until": "..."}`.
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_1.sh`
  - How it runs: Starts the Sentinel server with `TRUST_PROXY=true` (`uvicorn app.main:app`). Issues 10 failed login `curl` requests with `-H "X-Forwarded-For: 198.51.100.10"`. Demonstrates that the 11th `curl` request is blocked with `HTTP 403 Forbidden` and displays the ban end time.

---

### Killer Test 2 — Innocent Bystander Isolation

**Given** an attacker IP (`198.51.100.10`) has exceeded the threshold and is actively banned,  
**When** a legitimate user from a distinct IP (`203.0.113.50`) submits valid login credentials (`student:secret2024`) to `POST /login`,  
**Then** the legitimate user's request is allowed through by Blocker middleware, returning `HTTP 200 OK` (`Login successful`), proving that only the attacker IP is isolated and banned.

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_2_bystander_isolation.py`
  - How it runs: Triggers a ban for attacker IP `198.51.100.10` via 10 failed attempts with `X-Forwarded-For: 198.51.100.10`. Concurrently or immediately after, sends valid login credentials with `X-Forwarded-For: 203.0.113.50`. Asserts attacker receives `HTTP 403 Forbidden` while normal user receives `HTTP 200 OK`.
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_2.sh`
  - How it runs: Starts server with `TRUST_PROXY=true`. Issues 10 failed login `curl` requests with `-H "X-Forwarded-For: 198.51.100.10"`. Then sends a valid login `curl` with `-H "X-Forwarded-For: 203.0.113.50"` and credentials `student:secret2024`. Displays terminal output showing `198.51.100.10` returning `403` and `203.0.113.50` returning `200 OK` from the same laptop.

---

### Killer Test 3 — Exact Expiry

**Given** an IP (`198.51.100.10`) has an active ban with a short duration (e.g. `BAN_DURATION_SECONDS=2`),  
**When** the exact expiration timestamp is reached (`now >= until`),  
**Then** the IP is immediately unblocked and allowed through on the next request without delay, even with the background Expiry Sweeper disabled.

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_3_exact_expiry.py`
  - How it runs: Configures `BAN_DURATION_SECONDS=2` and stops or mocks the background sweeper to prove independence. Triggers a ban for `198.51.100.10`, asserts `HTTP 403 Forbidden` while $t < until$, sleeps 2.1 seconds, and immediately asserts the next request is no longer blocked (returns `HTTP 200 OK` or `401 Unauthorized` on bad password, but never `403`).
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_3.sh`
  - How it runs: Starts server with `TRUST_PROXY=true` and `BAN_DURATION_SECONDS=2`. Simulates brute force using `-H "X-Forwarded-For: 198.51.100.10"`, displays `HTTP 403 Forbidden`, waits 2 seconds, and issues another `curl` request showing immediate access restoration (`200 OK`) as soon as the ban window expires.

---

### AI Explainer Acceptance Criteria

**Given** the `AI_API_KEY` configuration is not set in `.env`,  
**When** the Sentinel service starts and creates an alert,  
**Then** the service logs an informational notice that AI explanation is disabled, saves the alert with `ai_explanation = null`, and continues normal detection and banning operations.

**Given** the `AI_API_KEY` configuration is set in `.env`,  
**When** an attack threshold is reached and an alert is created,  
**Then** Sentinel triggers an asynchronous background task sending non-secret incident context (alert ID, source IP, scenario, failure count, window, timestamp) to Groq's OpenAI-compatible chat completions API (`llama-3.1-8b-instant`) with a 5.0-second timeout and zero retries, and saves the resulting plain-English summary to `alert.ai_explanation`. Ban creation and Blocker enforcement are never blocked or delayed, and if the AI request times out or errors, `ai_explanation` remains null.

---

### Admin Visibility Acceptance Criteria

**Given** active bans and historical alerts exist in SQLite,  
**When** an administrator sends authenticated `GET` requests to `/v1/decisions` and `/v1/alerts` with `X-Api-Key`,  
**Then** Sentinel returns JSON arrays containing active bans (with `ip`, `scenario`, `until`) and recorded alerts.

---

## 8. Configuration & Environment Variables

All runtime settings and thresholds are loaded strictly from environment variables (e.g. `.env` via `pydantic-settings`):

| Variable | Default Value | Description |
|---|---|---|
| `BAN_THRESHOLD` | `10` | Number of failed login attempts within window required to trigger a ban. |
| `WINDOW_SECONDS` | `60` | Duration in seconds of the sliding detection window. |
| `BAN_DURATION_SECONDS` | `300` | Duration of the ban in seconds (automated tests override with short value e.g. 2s). |
| `LOG_FILE_PATH` | `portal_auth.log` | Path to log file written synchronously by portal and read by watcher. |
| `DATABASE_URL` | `sqlite:///./sentinel.db` | Local SQLite database file location. |
| `ADMIN_API_KEY` | `sentinel-admin-secret-key` | Secret key for `/v1/*` admin endpoints via `X-Api-Key` header. Loaded from env; never hardcoded. |
| `AI_API_KEY` | `""` | Optional external LLM API key for Groq. If empty or absent, AI explanation is disabled gracefully. |
| `TRUST_PROXY` | `false` | Boolean (`true`/`false`). When `false`, uses connection socket IP; when `true`, parses `X-Forwarded-For`. |
