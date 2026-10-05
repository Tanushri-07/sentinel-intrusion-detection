# Gaps — CrowdSec Analysis & Sentinel Improvements

---

## Verified Gaps in the Original CrowdSec System

### Gap 1: Query-Time-Only Decision Expiry

| Property | Detail |
|---|---|
| **Gap** | Decision expiry is enforced only at query time via a `WHERE until > now()` filter. There is no proactive mechanism to notify bouncers when a decision expires. A bouncer only discovers a decision has expired on its next poll cycle. |
| **Type** | Correctness / UX |
| **Evidence** | `pkg/database/decisions.go:33` — `decision.UntilGT(now)` [Confirmed]. `pkg/apiserver/controllers/v1/decisions.go:23` — remaining duration computed as `Until.Sub(time.Now().UTC())` [Confirmed]. No background expiry job that pushes notifications was found. |
| **Who it hurts** | End users whose IPs are banned. If a bouncer polls every 30 seconds, a ban could persist up to 30 seconds past its intended expiry. |
| **Suggested fix** | Add proactive request-time exact evaluation in middleware so that bans vanish the millisecond `until` is reached, with a background sweeper cleaning stale records. |
| **Severity** | Medium |

### Gap 2: Commented-Out v2 API

| Property | Detail |
|---|---|
| **Gap** | The entire v2 API route group is commented out and non-functional. |
| **Type** | Docs drift / Dead code |
| **Evidence** | `pkg/apiserver/controllers/controller.go:161-193` — entire block wrapped in `/* ... */` [Confirmed] |
| **Who it hurts** | Maintainers who may expect v2 to be available. |
| **Suggested fix** | Remove dead code or implement cleanly in new rebuild. |
| **Severity** | Low |

### Gap 3: No Rate Limiting on Machine Registration

| Property | Detail |
|---|---|
| **Gap** | The `POST /v1/watchers` endpoint (machine registration) has a body size limit but no per-IP rate limiting. An attacker could rapidly create many machine registrations. |
| **Type** | Security |
| **Evidence** | `pkg/apiserver/controllers/controller.go:118` — only `unauthBodyLimit` middleware is applied, no rate limiter [Likely] |
| **Who it hurts** | LAPI operators; could be used for resource exhaustion. |
| **Suggested fix** | Add per-IP rate limiting or eliminate machine registration altogether in a unified single-process architecture. |
| **Severity** | Medium |

### Gap 4: No Bouncer-to-Decision Relationship in Database

| Property | Detail |
|---|---|
| **Gap** | The Bouncer entity has no edge to Decision or Alert. There is no database-level audit trail of which decisions a specific bouncer has received or is enforcing. |
| **Type** | Data / Observability |
| **Evidence** | `pkg/database/ent/schema/bouncer.go:48-50` — `Edges() returns nil` [Confirmed]. Stream cursor at `bouncer.go:36` [Confirmed]. |
| **Who it hurts** | Operators trying to debug enforcement issues. |
| **Suggested fix** | Use an inline middleware blocker that directly accesses the decision store. |
| **Severity** | Low |

---

## Selected Improvements for Our Rebuild

The Sentinel rebuild selects one architectural Gap Fix and one high-value Differentiator, both implementable within the locked Python 3.11+ / FastAPI / SQLite / pytest stack.

---

### Improvement 1: Gap Fix — Exact Request-Time Expiry & Sweeper Cleanup

**What we fix**: CrowdSec relies on polling bouncers that query decisions at coarse intervals (e.g. 10–30s). When a ban expires, an innocent or unbanned user remains blocked until the bouncer's next poll.

**How Sentinel fixes it**:
1. **Request-Time Dynamic Check**: The inline Blocker ASGI middleware checks `until > now` on every incoming HTTP request. The exact millisecond `now >= until`, the request passes through cleanly with `HTTP 200 OK` (or appropriate application response), achieving zero-delay ban expiration.
2. **Background Expiry Sweeper**: A periodic background task handles database hygiene by updating past records (`UPDATE decision SET active = 0 WHERE until <= :now`). The sweeper is purely for cleanup; the request-time check ensures exact unblocking whether the sweeper runs or not.

**Why it matters**: For a university portal during result week, legitimate students must not suffer extended lockouts due to polling lag.

**Demonstrated by Killer Test 3**:
- Automated test: `pytest -v tests/test_killer_3_exact_expiry.py` with `BAN_DURATION_SECONDS=2` and sweeper stopped, demonstrating immediate unblocking upon expiration.
- Manual script: `bash scripts/demo_killer_3.sh`.

---

### Improvement 2: Differentiator — AI-Powered Threat Explanation

**What the original lacks**: CrowdSec produces alert records with numeric scenario IDs and source IPs, but requires human operators to manually interpret raw attack details.

**What Sentinel adds**: An optional AI Threat Explainer component that calls an external LLM API to produce a concise, plain-English explanation of detected attack patterns.

**Design & Portability**:
- **Fully Optional**: The Sentinel service operates completely without an AI key. If `AI_API_KEY` is empty or missing in `.env`, the system functions normally; alerts are saved with `ai_explanation = null`.
- **Environment Driven**: Key is configured via `AI_API_KEY` in `.env`. No hardcoded credentials or external dependencies exist in source code.
- **Admin Visibility**: Admins can view explanations via `GET /v1/alerts/{id}/explain` or within the alert payload.

**Demonstrated by**:
- Alert creation with `AI_API_KEY` populated attaches an explanation to the incident report.
- Alert creation without `AI_API_KEY` logs a graceful fallback notice and continues uninterrupted.

---

## Summary

| # | Improvement | Category | Stack / Implementation |
|---|---|---|---|
| 1 | Exact request-time ban expiry with sweeper cleanup | Gap Fix (Gap 1) | Blocker ASGI middleware evaluating `until > now` + SQLite background cleanup task |
| 2 | AI-powered incident threat explanation | Differentiator | Optional LLM integration via `AI_API_KEY` in `.env` |
