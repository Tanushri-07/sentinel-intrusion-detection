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

## 4. Core Flow

1. The university portal (**Demo Portal**) receives authentication attempts (`POST /login`) and writes structured log lines to `portal_auth.log`.
2. Sentinel's **Log Watcher** tails the log file and emits raw log lines into an in-memory queue/channel.
3. The **Log Parser** transforms each raw line into a structured event (`timestamp`, `ip`, `username`, `result`).
4. The **Attack Detector** receives parsed events and maintains per-IP sliding time windows. It evaluates configured scenarios (e.g. `BAN_THRESHOLD` failed logins within `WINDOW_SECONDS`).
5. When the threshold is exceeded, the detector creates an **Alert** and a **Ban Decision** with `until = now + BAN_DURATION_SECONDS` in SQLite.
6. The **Blocker** middleware intercepts incoming requests to the portal. It checks SQLite for an active decision where `until > now`. If active, it immediately returns `HTTP 403 Forbidden` with the ban expiry timestamp.
7. The moment `now >= until`, the request passes through cleanly. The **Expiry Sweeper** cleans up stale database records in the background.

---

## 5. Scope Boundaries

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

## 6. Acceptance Criteria & Killer Test Execution

The system's correctness is validated through three Killer Tests, each runnable via an automated `pytest` test and a standalone manual demo script.

### Killer Test 1 — Brute-Force Detection

**Scenario**: One attacker IP generates 10 failed login attempts within 60 seconds (`BAN_THRESHOLD=10`, `WINDOW_SECONDS=60`). Upon the 10th failure, the IP is automatically banned. Subsequent requests return `HTTP 403 Forbidden` with the ban expiry time.

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_1_brute_force.py`
  - How it runs: The test initializes an in-memory or test SQLite database, mounts the Blocker middleware and Demo Portal, sends 10 consecutive invalid `POST /login` requests with `client.host = "198.51.100.10"`, processes log pipeline events, and verifies that the 11th request returns `403 Forbidden` with a JSON body containing `{"error": "IP is banned", "ip": "198.51.100.10", "until": "..."}`.
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_1.sh`
  - How it runs: Starts the Sentinel server (`uvicorn app.main:app`), uses `curl` to issue 10 failed login attempts against `http://localhost:8000/login` with attacker IP header or socket, and displays the 11th request being blocked with `HTTP 403` and the ban end time.

---

### Killer Test 2 — Innocent Bystander Isolation

**Scenario**: While an attacker IP is generating failed logins and gets banned, an innocent user logging in from a distinct IP is completely unaffected and continues to authenticate successfully.

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_2_bystander_isolation.py`
  - How it runs: Attacker IP (`198.51.100.10`) sends 10 failed logins and is banned. Concurrently or immediately after, legitimate user IP (`203.0.113.50`) sends a valid `POST /login` (`student:secret2024`). The test verifies that the legitimate request returns `HTTP 200 OK` (`Login successful`) and is never blocked.
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_2.sh`
  - How it runs: Script triggers 10 failed attempts from IP A (banned), then issues `curl` from IP B with valid credentials, verifying IP A receives `403 Forbidden` while IP B receives `200 OK`.

---

### Killer Test 3 — Exact Expiry

**Scenario**: An IP is banned with a short duration (e.g. `BAN_DURATION_SECONDS=2`). While $t < until$, requests return `HTTP 403`. Exactly when $t \ge until$, the IP is immediately unblocked and allowed through, even with the background Expiry Sweeper disabled.

- **Automated pytest execution**:
  - Command: `pytest -v tests/test_killer_3_exact_expiry.py`
  - How it runs: Configures `BAN_DURATION_SECONDS=2`, disables or mocks the background sweeper to prove independence, triggers a ban for IP `198.51.100.10`, verifies `HTTP 403` during the 2-second ban, sleeps 2.1 seconds, and immediately asserts the next request returns `HTTP 200 OK` (or `401` on invalid credentials, but not `403`).
- **Manual demo script execution**:
  - Command: `bash scripts/demo_killer_3.sh`
  - How it runs: Performs brute force with 2-second ban duration, shows 403 response, pauses for 2 seconds, and demonstrates immediate access restored upon expiration.

---

### AI Explainer Acceptance Criteria

- **When `AI_API_KEY` is not set**: Sentinel starts cleanly, logs an info notice that AI explanation is disabled, and all detection, banning, and unblocking functions execute without error.
- **When `AI_API_KEY` is set**: When an alert is created, the system calls the LLM to generate an explanation of the attack pattern, saving it to the `alert.ai_explanation` field.

### Admin Visibility Acceptance Criteria

- `GET /v1/decisions` returns active bans with IP, scenario, and expiry time.
- `GET /v1/alerts` returns all generated alerts and their incident details.
