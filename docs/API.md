# API Specification — Sentinel Intrusion Detection

---

## Overview

Sentinel runs as a unified FastAPI web service hosting:
1. **Demo Portal Endpoints**: Endpoints representing the university student portal protected by the Blocker middleware (e.g. `POST /login`).
2. **Admin API Endpoints**: Endpoints for IT administrators to monitor and manage bans, alerts, and system health.
3. **Blocker Middleware**: Intercepts requests before reaching application handlers, enforcing active bans.

All requests and responses use JSON format unless otherwise noted.

---

## Configuration & Environment Variables

| Variable | Default Value | Description |
|---|---|---|
| `BAN_THRESHOLD` | `10` | Failed logins within window required to trigger a ban. |
| `WINDOW_SECONDS` | `60` | Duration in seconds of the sliding detection window. |
| `BAN_DURATION_SECONDS` | `300` | Duration in seconds for an automated ban. |
| `LOG_FILE_PATH` | `portal_auth.log` | Path to log file written by portal and read by watcher. |
| `DATABASE_URL` | `sqlite:///./sentinel.db` | SQLite database file location. |
| `ADMIN_API_KEY` | `sentinel-admin-secret-key` | Secret key for `/v1/*` admin endpoints via `X-Api-Key` header. |
| `AI_API_KEY` | `""` | Optional external LLM API key. System functions without it. |
| `TRUST_PROXY` | `false` | Whether to read client IP from `X-Forwarded-For` (`true`) or connection socket (`false`). |

---

## Client IP Resolution Rules

Client IP is determined consistently across the Blocker middleware, Demo Portal, and logging subsystem:
- **When `TRUST_PROXY=false` (default)**: Extract IP from the ASGI socket connection address (`request.client.host`). Ignores `X-Forwarded-For`.
- **When `TRUST_PROXY=true`**: Extract IP from the first (leftmost) comma-separated value in the `X-Forwarded-For` HTTP header, trimmed of whitespace. If the header is missing or empty, fall back to the connection socket address.

---

## Blocker Middleware Enforcement

Positioned in front of the Demo Portal and protected routes.

- **Check**: Runs before every request:
  `SELECT until FROM decision WHERE value = :client_ip AND type = 'ban' AND until > :now;`
- **Response when Banned**:
  - **Status Code**: `403 Forbidden`
  - **Body**:
    ```json
    {
      "error": "IP is banned",
      "ip": "198.51.100.10",
      "until": "2026-10-05T22:35:00Z"
    }
    ```
- **Response when Not Banned**: Forwards request down the ASGI chain.

---

## Demo Portal Endpoints

### 1. User Login

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/login` |
| **Purpose** | Authenticate student or staff against seeded demo user credentials. |
| **Authentication** | None (public endpoint protected by Blocker middleware). |
| **Request Body** | JSON: `{"username": "student", "password": "secret2024"}` |
| **Seeded Users** | `alice:password123`, `student:secret2024`, `admin:adminpass` |

#### Request Validation & Logging Rules
- FastAPI schema validation applies to the incoming JSON body.
- If JSON is malformed, required fields (`username`, `password`) are missing, or fields fail schema validation, FastAPI immediately returns `HTTP 422 Unprocessable Entity`.
- **When HTTP 422 occurs, DO NOT append a `portal_auth.log` line** because the login handler was never entered.
- Usernames containing the pipe character `|` are rejected during schema validation so the log delimiter remains strictly unambiguous.
- Passwords are NEVER written to logs or stored in databases.

**Responses**:
- `200 OK` (Valid credentials):
  ```json
  {
    "status": "success",
    "message": "Login successful"
  }
  ```
- `401 Unauthorized` (Invalid credentials):
  ```json
  {
    "status": "fail",
    "detail": "Invalid username or password"
  }
  ```
- `403 Forbidden` (Client IP is banned by Blocker middleware):
  ```json
  {
    "error": "IP is banned",
    "ip": "198.51.100.10",
    "until": "2026-10-05T22:35:00Z"
  }
  ```
- `422 Unprocessable Entity` (Schema validation failure):
  ```json
  {
    "detail": [
      {
        "loc": ["body", "username"],
        "msg": "field required",
        "type": "value_error.missing"
      }
    ]
  }
  ```

#### Structured Log Output Requirement
Every request that passes schema validation MUST append exactly one line to `portal_auth.log` (`LOG_FILE_PATH`) with a single atomic append operation followed by a newline:
```
{timestamp} | ip={ip} | username={username} | result=success|fail
```
- **Timestamp**: ISO 8601 UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` (e.g. `2026-10-05T22:30:00Z`).
- **IP**: Resolved client IP string.
- **Username**: Submitted username (stripped of leading/trailing whitespace).
- **Result**: Exactly `success` (valid credentials) or `fail` (invalid credentials).

---

## Admin API Endpoints

All admin endpoints (mounted under `/v1/*`) require authentication via HTTP header:
`X-Api-Key: <ADMIN_API_KEY>`

- `/health` is **public** and requires no authentication.
- For every `/v1/*` endpoint, if `X-Api-Key` is missing, empty, or does not match `ADMIN_API_KEY` loaded from the environment, the endpoint immediately returns:
  - **Status Code**: `401 Unauthorized`
  - **Body**:
    ```json
    {
      "detail": "Invalid or missing API key"
    }
    ```
- `ADMIN_API_KEY` is loaded strictly from environment configuration (`.env`). Real secrets must never be hardcoded into source code or committed to repositories.

### 2. Health Check

- **Method**: `GET`
- **Path**: `/health`
- **Auth**: None
- **Response**: `200 OK`
  ```json
  {
    "status": "ok",
    "service": "sentinel"
  }
  ```

### 3. List Active Decisions (Bans)

- **Method**: `GET`
- **Path**: `/v1/decisions`
- **Auth**: `X-Api-Key`
- **Query Parameters**: `ip` (optional filter)
- **Response**: `200 OK`
  ```json
  [
    {
      "id": 1,
      "scope": "ip",
      "value": "198.51.100.10",
      "type": "ban",
      "scenario": "brute_force_login",
      "origin": "sentinel",
      "until": "2026-10-05T22:35:00Z",
      "active": 1,
      "created_at": "2026-10-05T22:30:00Z"
    }
  ]
  ```

### 4. Check IP Ban Status

- **Method**: `GET`
- **Path**: `/v1/decisions/check/{ip}`
- **Auth**: `X-Api-Key`
- **Response**: `200 OK`
  ```json
  {
    "banned": true,
    "ip": "198.51.100.10",
    "until": "2026-10-05T22:35:00Z"
  }
  ```
  Or when not banned:
  ```json
  {
    "banned": false,
    "ip": "203.0.113.50",
    "until": null
  }
  ```

### 5. Manually Remove Decision (Unban IP)

- **Method**: `DELETE`
- **Path**: `/v1/decisions/{decision_id}`
- **Auth**: `X-Api-Key`
- **Response**: `200 OK`
  ```json
  {
    "deleted": true,
    "decision_id": 1
  }
  ```

### 6. List Alerts

- **Method**: `GET`
- **Path**: `/v1/alerts`
- **Auth**: `X-Api-Key`
- **Response**: `200 OK`
  ```json
  [
    {
      "id": 1,
      "scenario": "brute_force_login",
      "source_ip": "198.51.100.10",
      "event_count": 10,
      "started_at": "2026-10-05T22:29:10Z",
      "stopped_at": "2026-10-05T22:30:00Z",
      "message": "10 failed logins in 50 seconds",
      "ai_explanation": "Automated brute-force password guessing detected against user 'student'.",
      "created_at": "2026-10-05T22:30:00Z"
    }
  ]
  ```

### 7. Get AI Explanation for Alert

- **Method**: `GET`
- **Path**: `/v1/alerts/{alert_id}/explain`
- **Auth**: `X-Api-Key`
- **Response**: `200 OK`
  ```json
  {
    "alert_id": 1,
    "ai_explanation": "Automated brute-force attack detected from 198.51.100.10 targeting user accounts."
  }
  ```
  *(Returns `{"alert_id": 1, "ai_explanation": null, "message": "AI explanation disabled (AI_API_KEY not configured)"}` if no key is set).*


### 8. Manually Create Decision (Ban IP)

| Property | Value |
|---|---|
| **Method** | `POST` |
| **Path** | `/v1/decisions` |
| **Auth** | `X-Api-Key: <ADMIN_API_KEY>` (returns 401 if missing/invalid) |
| **Purpose** | Allows administrators to manually ban an IP address for a specified duration. |

#### Request Body
```json
{
  "value": "198.51.100.10",
  "duration_seconds": 3600,
  "scenario": "manual"
}
```

| Field | Type | Required | Default | Validation Rules | Description |
|---|---|---|---|---|---|
| `value` | string | yes | | Valid IPv4 or IPv6 address | IP address to ban |
| `duration_seconds` | integer | yes | | Integer > 0 | Ban duration in seconds |
| `scenario` | string | no | `"manual"` | String | Reason or scenario label |

#### Validation & Constraints
- If `value` is not a valid IPv4/IPv6 address or `duration_seconds <= 0`, returns `HTTP 422 Unprocessable Entity`.
- Decision is inserted into SQLite with:
  - `scope = "ip"`
  - `value = request.value`
  - `type = "ban"`
  - `scenario = request.scenario or "manual"`
  - `origin = "admin"` (or `"sentinel"`)
  - `until = current_utc_time + duration_seconds`
  - `active = 1`
  - `alert_id = NULL`

#### Responses
- `201 Created`:
  ```json
  {
    "id": 2,
    "scope": "ip",
    "value": "198.51.100.10",
    "type": "ban",
    "scenario": "manual",
    "origin": "admin",
    "until": "2026-10-05T23:35:00Z",
    "active": 1,
    "created_at": "2026-10-05T22:35:00Z"
  }
  ```
- `401 Unauthorized` (Missing or invalid `X-Api-Key`):
  ```json
  {
    "detail": "Invalid or missing API key"
  }
  ```
- `422 Unprocessable Entity` (Invalid IP format or duration):
  ```json
  {
    "detail": "Invalid IP address or duration"
  }
  ```