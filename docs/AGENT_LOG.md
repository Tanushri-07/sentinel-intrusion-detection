# Agent Log — Reverse-Engineering & Architecture Specification Record

---

## Stage 0: Orientation

**What we asked**: What does CrowdSec do? Top-level folder structure. Language, build system, entry points. Where log parsing, scenarios, decisions, and bouncer enforcement live.

**What was learned**:
- CrowdSec is a Go-based collaborative IPS.
- Three binaries: `crowdsec` (agent), `crowdsec-cli` (`cscli`), notification plugins.
- Log parsing lives in `pkg/parser/` and `pkg/acquisition/`.
- Scenarios use leaky buckets in `pkg/leakybucket/`.
- Decisions are stored via `pkg/database/` and served by `pkg/apiserver/`.
- Bouncer enforcement is external; bouncers poll LAPI.

**Corrections**: None.
**Uncertainty**: Specific bouncer implementations are external repositories.

---

## Stage 1: Architecture Map

**What was learned**:
- Decoupled Agent + LAPI architecture.
- Agent pipeline: acquisition → parser (s00→s01→s02) → leaky bucket → output → LAPI.
- Go channels connect pipeline stages (`logLines`, `inEvents`, `outEvents`).
- LAPI uses Gin framework, stores to Ent/database, serves decisions to bouncers via API-key-auth endpoints.

---

## Stage 2: Data Model

**What was learned**:
- Six core entities (`Alert`, `Decision`, `Event`, `Meta`, `Machine`, `Bouncer`).
- `Alert` → `Decision`/`Event`/`Meta` (one-to-many, CASCADE delete).
- Decision expiry uses `until` field.
- Decision indexes include `(until)`, `(value, type, scope, until, simulated)`.

---

## Stage 3: Routes and Entry Points

**What was learned**:
- Routes registered in `pkg/apiserver/controllers/controller.go`.
- JWT-authenticated group: `POST /v1/watchers`, `POST /v1/alerts`, `DELETE /v1/decisions`, etc.
- API-key-authenticated group: `GET /v1/decisions`, `GET /v1/decisions/stream`.
- Health endpoint: `GET /health`.
- v2 API group is entirely commented out.

---

## Stage 4: Data Model Documentation

**What was learned**:
- Relationships stored via foreign keys in Ent schema.
- Cascade deletes on `Alert` → `Decision`/`Event`/`Meta`.

---

## Stage 5: End-to-End Feature Trace

**What was learned**:
- Full lifecycle traced: log tailing → grok parser → leaky bucket pour → overflow → alert creation → decision storage → bouncer polling → query-time expiry.

---

## Stage 6: Screenshots + Journey

**What was learned**:
- Verified CLI commands against LAPI endpoints (`cscli alerts list`, `cscli decisions list`).

---

## Stage 7: Gaps Analysis

**What was learned**:
- Gap 1: Decision expiry is query-time only; bouncers poll periodically, causing stale bans.
- Gap 2: Commented-out v2 API.
- Gap 3: No rate limiting on machine registration.
- Gap 4: No database-level bouncer audit trail.

---

## Stage 8: Verification

**What was learned**:
- Source lines re-checked and verified against active Go code in the CrowdSec repository.

---

## Stage 9: Specification & Architecture Lock (Current)

**Why the docs were updated**:
Updated documentation across `docs/` so that any independent AI agent can build the complete Sentinel system without ambiguities, unstated assumptions, or reading the README:
- **Locked Rebuild Stack**: Explicitly locked to Python 3.11+, FastAPI (ASGI), SQLite, and pytest.
- **Demo Portal Component**: Specified `POST /login` with seeded credentials (`alice:password123`, `student:secret2024`, `admin:adminpass`) and an exact log line format: `{timestamp} | ip={ip} | username={username} | result=success|fail` appended synchronously to `portal_auth.log`.
- **Inline Blocker ASGI Middleware**: Placed in front of Demo Portal. Evaluates `until > now` on every incoming request. If active, returns `HTTP 403 Forbidden` with the ban expiry timestamp. Clarified that this request-time check guarantees exact-to-the-millisecond unblocking, while the Expiry Sweeper solely handles background database hygiene.
- **Configuration (.env)**: Formalized environment parameters: `BAN_THRESHOLD`, `WINDOW_SECONDS`, `BAN_DURATION_SECONDS`, `LOG_FILE_PATH`, `DATABASE_URL`, `ADMIN_API_KEY`, `AI_API_KEY`, and `TRUST_PROXY`.
- **Client IP Resolution**: Defined socket-based IP extraction by default (`TRUST_PROXY=false`) and `X-Forwarded-For` parsing only when `TRUST_PROXY=true`.
- **Killer Tests Execution**: Documented both automated `pytest` and manual demo script commands and execution details for all 3 Killer Tests in `PRD.md`.
- **Preserved Observations & Gaps**: Verified CrowdSec findings preserved; gap fix and differentiator clearly partitioned and aligned with the rebuild stack.
---

## Canonical Project Root & Specification

Canonical project root:
`/Users/tanushri/Desktop/sentinel-intrusion-detection`

Canonical specification:
`/Users/tanushri/Desktop/sentinel-intrusion-detection/docs/`

All implementation work must use this repository and its `docs/` directory.

Do not create or maintain a second specification tree.
