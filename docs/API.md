# API — Sentinel Intrusion Detection

---

## Overview

Sentinel exposes an HTTP REST API for administrator visibility and for the Blocker to check active bans. All endpoints serve JSON. The API design is informed by CrowdSec's LAPI route structure (Evidence: pkg/apiserver/controllers/controller.go:117-156 [Confirmed]) but is simplified for our single-server use case.

---

## Authentication

| Role | Auth Method | Notes |
|---|---|---|
| Administrator | API key (header: `X-Api-Key`) | Admin API key configured at startup |
| Blocker (internal) | Localhost-only or shared secret | Unknown — exact mechanism TBD. The Blocker runs in the same process, so it may call the decision store directly without HTTP. |

---

## Routes

### 1. Health Check

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/health` |
| **Purpose** | Verify the service is running |
| **Input** | None |
| **Output** | `{ "status": "ok" }` |
| **Who may call** | Anyone (unauthenticated) |
| **Auth** | None |
| **Error cases** | 503 if service is unhealthy |

Inspired by CrowdSec's GET /health endpoint (Evidence: pkg/apiserver/controllers/controller.go:99 [Confirmed]).

---

### 2. List Active Decisions (Bans)

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/v1/decisions` |
| **Purpose** | Return all currently active ban decisions |
| **Input** | Query params: `ip` (optional, filter by IP), `scope` (optional) |
| **Output** | `[ { "id": 1, "value": "192.168.1.100", "type": "ban", "scenario": "brute_force_login", "until": "2025-01-15T10:30:00Z", "origin": "sentinel", "created_at": "..." } ]` |
| **Who may call** | Administrator, Blocker |
| **Auth** | API key or internal |
| **Error cases** | 401 Unauthorized, 500 Internal Server Error |

Inspired by CrowdSec's GET /v1/decisions (Evidence: pkg/apiserver/controllers/controller.go:146 [Confirmed]).

**Killer Test 3 relevance**: This endpoint only returns decisions where `active = true AND until > now()`. An expired decision will not appear.

---

### 3. Check IP

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/v1/decisions/check/:ip` |
| **Purpose** | Check whether a specific IP is currently banned |
| **Input** | Path param: `ip` |
| **Output** | `{ "banned": true, "decisions": [...] }` or `{ "banned": false }` |
| **Who may call** | Blocker, Administrator |
| **Auth** | API key or internal |
| **Error cases** | 400 Bad Request (invalid IP), 401 Unauthorized, 500 Internal Server Error |

**Killer Test 2 relevance**: The Blocker calls this for each incoming request. Only the attacker's IP returns `banned: true`.

**Killer Test 3 relevance**: Returns `banned: false` once the decision's `until` timestamp has passed.

---

### 4. List Alerts

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/v1/alerts` |
| **Purpose** | Return alerts (detected attack patterns) |
| **Input** | Query params: `scenario` (optional), `source_ip` (optional), `since` (optional, datetime) |
| **Output** | `[ { "id": 1, "scenario": "brute_force_login", "source_ip": "192.168.1.100", "event_count": 10, "started_at": "...", "stopped_at": "...", "message": "...", "ai_explanation": "..." or null, "created_at": "..." } ]` |
| **Who may call** | Administrator |
| **Auth** | API key |
| **Error cases** | 401 Unauthorized, 500 Internal Server Error |

Inspired by CrowdSec's GET /v1/alerts (Evidence: pkg/apiserver/controllers/controller.go:126 [Confirmed]).

---

### 5. Get Alert by ID

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/v1/alerts/:alert_id` |
| **Purpose** | Return a single alert with its associated events and decisions |
| **Input** | Path param: `alert_id` |
| **Output** | `{ "id": 1, "scenario": "...", "source_ip": "...", "events": [...], "decisions": [...], "ai_explanation": "..." or null }` |
| **Who may call** | Administrator |
| **Auth** | API key |
| **Error cases** | 401, 404 Not Found, 500 |

---

### 6. Delete Decision

| Property | Value |
|---|---|
| **Method** | DELETE |
| **Path** | `/v1/decisions/:decision_id` |
| **Purpose** | Manually remove a ban (admin override) |
| **Input** | Path param: `decision_id` |
| **Output** | `{ "deleted": true }` |
| **Who may call** | Administrator |
| **Auth** | API key |
| **Error cases** | 401, 404, 500 |

Inspired by CrowdSec's DELETE /v1/decisions/:decision_id (Evidence: pkg/apiserver/controllers/controller.go:133 [Confirmed]).

---

### 7. Add Manual Decision

| Property | Value |
|---|---|
| **Method** | POST |
| **Path** | `/v1/decisions` |
| **Purpose** | Manually ban an IP (admin override) |
| **Input** | JSON body: `{ "value": "192.168.1.200", "type": "ban", "duration": "4h", "scenario": "manual", "origin": "admin" }` |
| **Output** | `{ "id": 5, "value": "192.168.1.200", "until": "..." }` |
| **Who may call** | Administrator |
| **Auth** | API key |
| **Error cases** | 400 (invalid input), 401, 500 |

---

### 8. Get AI Explanation

| Property | Value |
|---|---|
| **Method** | GET |
| **Path** | `/v1/alerts/:alert_id/explain` |
| **Purpose** | Get or generate an AI explanation for an alert |
| **Input** | Path param: `alert_id` |
| **Output** | `{ "explanation": "This alert indicates a brute-force password guessing attack..." }` or `{ "explanation": null, "reason": "AI not configured" }` |
| **Who may call** | Administrator |
| **Auth** | API key |
| **Error cases** | 401, 404, 500, 503 (AI service unavailable) |

**Differentiator relevance**: This endpoint is unique to Sentinel. CrowdSec has no AI explanation feature.

---

## Decisions Not Yet Made

- **Exact auth mechanism for Blocker**: Unknown. Since Blocker is in-process, it may bypass HTTP entirely and call the decision store directly.
- **Pagination**: Unknown. Whether list endpoints support pagination.
- **Rate limiting**: Unknown. Whether API endpoints are rate-limited.
- **Response envelope**: Unknown. Whether responses use a standard envelope (e.g., `{ "data": [...], "meta": {...} }`).
