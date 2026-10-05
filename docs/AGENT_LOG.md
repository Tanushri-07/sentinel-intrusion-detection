# Agent Log — Reverse-Engineering Conversation Record

---

## Stage 0: Orientation

**What we asked**: What does CrowdSec do? Top-level folder structure. Language, build system, entry points. Where log parsing, scenarios, decisions, and bouncer enforcement live.

**What was learned**:
- CrowdSec is a Go-based collaborative IPS (modern fail2ban alternative).
- Three binaries: crowdsec (agent), crowdsec-cli (cscli), notification plugins.
- Log parsing lives in pkg/parser/ and pkg/acquisition/.
- Scenarios use leaky buckets in pkg/leakybucket/.
- Decisions are stored via pkg/database/ and served by pkg/apiserver/.
- Bouncer enforcement is external; bouncers poll LAPI.

**Corrections**: None.
**Uncertainty**: Specific bouncer implementations are external repositories, not in this repo.

---

## Stage 1: Architecture Map

**What we asked**: List main components, how they communicate, Mermaid flowchart, key files/packages/structs for each subsystem.

**What was learned**:
- Decoupled Agent + LAPI architecture.
- Agent pipeline: acquisition → parser (s00→s01→s02) → leaky bucket → output → LAPI.
- Go channels connect pipeline stages (logLines, inEvents, outEvents).
- LAPI uses Gin framework, stores to Ent/database, serves decisions to bouncers via API-key-auth endpoints.
- Key structs: BucketSpec, BucketFactory, Leaky, pipeline.Event, APIServer.

**Corrections**: None.
**Uncertainty**: Bouncer internal polling loop implementation is UNVERIFIED (external repo).

---

## Stage 2: Data Model

**What we asked**: Inspect Ent schema definitions under pkg/database/ent/schema/. List every field for Alert, Decision, Event, Meta, Machine, Bouncer with types, constraints, indexes, and relationships.

**What was learned**:
- Six core entities with full field definitions.
- Alert → Decision/Event/Meta (one-to-many, CASCADE delete).
- Machine → Alert (one-to-many).
- Bouncer has no edges to other entities.
- Decision expiry uses `until` field (Time, nillable, optional).
- Decision indexes include (until), (value, type, scope, until, simulated).

**Corrections**: None.
**Uncertainty**: None for schema definitions — all verified from source files.

---

## Stage 3: Routes and Entry Points

**What we asked**: List every API route and CLI entry point with method, path, handler, input, output, auth check.

**What was learned**:
- All routes registered in pkg/apiserver/controllers/controller.go.
- JWT-authenticated group: POST/GET/DELETE for /v1/alerts, DELETE for /v1/decisions, POST /v1/watchers, etc.
- API-key-authenticated group: GET /v1/decisions, GET /v1/decisions/stream.
- Health endpoint: GET /health (unauthenticated).
- Usage metrics: POST /v1/usage-metrics (either auth).
- v2 API group is entirely commented out.

**Corrections**: None.
**Uncertainty**: Full CLI subcommand tree not exhaustively verified.

---

## Stage 4: Data Model Documentation

**What we asked**: Mermaid erDiagram, relationship storage mechanisms, entity purpose table, unused entities/fields.

**What was learned**:
- Relationships stored via foreign keys (alert_decisions, alert_events, alert_metas) in the Ent schema.
- Machine → Alert via Ent edge (no explicit FK field; managed by Ent).
- Cascade deletes on Alert → Decision/Event/Meta.

**Corrections**: None.
**Uncertainty**: Whether some fields (e.g., sourceLatitude/Longitude on Alert) are actively used or vestigial is Unknown.

---

## Stage 5: End-to-End Feature Trace

**What we asked**: Trace the full lifecycle: failed SSH/HTTP logins → detection → ban → enforcement → expiry.

**What was learned**:
- Acquisition reads log file → logLines channel.
- Parser stages (s00-raw, s01-parse, s02-enrich) → parsed event on inEvents channel.
- PourItemToHolders evaluates Filter expr, GroupBy partitions by source_ip, pours into bucket.
- Bucket overflow → NewAlert + RuntimeAlert with decisions.
- Output routine POSTs alert to LAPI via HTTP.
- LAPI CreateAlert handler stores to database.
- Bouncer polls GET /v1/decisions with WHERE until > now() filter.
- Expiry: query-time only. Flush scheduler cleans up old records periodically.

**Corrections**: None.
**Uncertainty**: Exact notification plugin behavior for alerts is Unknown.

---

## Stage 6: Screenshots + Journey

**What we asked**: Analyze CrowdSec screenshots (cscli alerts list, cscli decisions list), map to code, trace the full journey.

**What was learned**:
- Screenshots show CLI table output of alerts (scenario, IP, AS, country, events count) and decisions (IP, scope, type, duration).
- CLI commands correspond to LAPI API calls (GET /v1/alerts, GET /v1/decisions).
- Full journey confirmed from acquisition → parsing → bucket → overflow → alert → decision → bouncer poll → query-time expiry.

**Corrections**: None.
**Uncertainty**: Exact CLI formatting code not exhaustively traced.

---

## Stage 7: Gaps Analysis

**What we asked**: Review the codebase for security, correctness, data, UX, and missing feature gaps.

**What was learned**:
- Gap 1: Decision expiry is query-time only. No proactive push to bouncers on expiry.
- Gap 2: v2 API is commented out (dead code).
- Gap 3: No rate limiting on POST /v1/watchers registration.
- Gap 4: Bouncer has no database edge to decisions/alerts (no audit trail of delivery).

**Corrections**: None.
**Uncertainty**: Some gaps initially identified were downgraded during Stage 8 verification.

---

## Stage 8: Verification

**What we asked**: Re-read every cited file:line and tag each claim as Confirmed, Likely, or Guess.

**What was learned**:
- Most claims were Confirmed by re-reading the exact source lines.
- Query-time expiry (decision.UntilGT) confirmed at pkg/database/decisions.go:33.
- v2 commented-out code confirmed at pkg/apiserver/controllers/controller.go:161-193.
- Rate limiting absence on /v1/watchers tagged as Likely (no rate limiter middleware found, but absence is hard to prove definitively).

**Corrections**: Some line numbers adjusted where they had drifted. No claims were dropped entirely.
**Uncertainty**: A few claims about CLI behavior remained Likely rather than Confirmed.

---

## Stage 9: Documentation

**What we asked**: Write seven documentation files for our Sentinel rebuild using only Confirmed and Likely claims.

**What was produced**: OBSERVATIONS.md, PRD.md, ARCHITECTURE.md, DATA_MODEL.md, API.md, GAPS.md, AGENT_LOG.md.

**Corrections**: N/A (current stage).
**Uncertainty**: Implementation details marked as "Unknown" throughout the docs where decisions have not been made.
