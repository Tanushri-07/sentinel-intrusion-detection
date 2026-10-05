# Observations — CrowdSec Repository Analysis

All claims below were verified against the checked-out repository. Only Confirmed and Likely claims are included.

---

## Tech Stack

- CrowdSec is written in Go.
  Evidence: go.mod in repository root [Confirmed]

- The HTTP framework is Gin (github.com/gin-gonic/gin).
  Evidence: pkg/apiserver/apiserver.go:17 [Confirmed]

- The ORM is Ent (entgo.io/ent), with schema source files under pkg/database/ent/schema/.
  Evidence: pkg/database/ent/schema/alert.go:4 [Confirmed]

- Scheduled jobs use gocron (github.com/go-co-op/gocron/v2).
  Evidence: pkg/apiserver/apiserver.go:18, pkg/database/flush.go:10 [Confirmed]

- Logging uses logrus (github.com/sirupsen/logrus).
  Evidence: pkg/apiserver/apiserver.go:19 [Confirmed]

---

## Repository Structure

- Three binaries are built from cmd/: crowdsec (agent/log processor), crowdsec-cli (cscli, admin CLI), and notification plugins under cmd/notification-*/.
  Evidence: cmd/crowdsec/, cmd/crowdsec-cli/, cmd/notification-*/ directories [Confirmed]

- Core library code lives under pkg/, including: acquisition, parser, leakybucket, apiserver, database, apiclient, csconfig, models, types, pipeline.
  Evidence: pkg/ directory listing [Confirmed]

---

## Architecture

- CrowdSec uses a decoupled Agent + Local API (LAPI) architecture. The agent reads logs, parses them, and pushes overflow alerts to LAPI over HTTP. LAPI stores data in a database and serves decisions to bouncers.
  Evidence: cmd/crowdsec/crowdsec.go:28-72, pkg/apiserver/apiserver.go:35-45 [Confirmed]

- The agent pipeline uses Go channels: logLines channel feeds parser routines, inEvents channel feeds bucket routines, outEvents channel is consumed by output routines that push alerts to LAPI.
  Evidence: cmd/crowdsec/crowdsec.go:176-177, lines 179-189 [Confirmed]

- Bouncers are external processes that poll LAPI for active decisions via API-key-authenticated endpoints.
  Evidence: pkg/apiserver/controllers/controller.go:143-150 [Confirmed]

---

## Log Acquisition

- The acquisition package (pkg/acquisition/) supports multiple data sources: file, journalctl, syslog, cloudwatch, kinesis, kafka, docker, loki, appsec, and others.
  Evidence: pkg/acquisition/ directory listing [Confirmed]

- acquisition.StartAcquisition writes raw log events into the logLines channel.
  Evidence: cmd/crowdsec/crowdsec.go:197 [Confirmed]

---

## Parsing

- Parsers are loaded via parser.LoadParsers and are organized in stages (s00-raw, s01-parse, s02-enrich).
  Evidence: cmd/crowdsec/crowdsec.go:43-46 [Confirmed]

- Parser routines read from logLines channel, process through parser stages, and write parsed events into inEvents channel.
  Evidence: cmd/crowdsec/crowdsec.go:100-108, line 105 [Confirmed]

---

## Events

- The Event entity stores a serialized event (max 8191 chars), a timestamp, and a foreign key to Alert via alert_events.
  Evidence: pkg/database/ent/schema/event.go:16-27 [Confirmed]

- Events have an edge back to Alert via edge.From("owner", Alert.Type).Ref("events").
  Evidence: pkg/database/ent/schema/event.go:31-37 [Confirmed]

---

## Scenarios / Detection (Leaky Buckets)

- Scenarios are defined as YAML BucketSpec structs with fields: Type (leaky, counter, trigger), Name, Capacity, LeakSpeed, Filter (expr), GroupBy (expr), Duration, and others.
  Evidence: pkg/leakybucket/manager_load.go:29-55 [Confirmed]

- The GroupBy expression (commonly evt.Meta.source_ip) determines the bucket partition key, so each source IP gets its own bucket instance.
  Evidence: pkg/leakybucket/manager_run.go:250-263 [Confirmed]

- PourItemToHolders evaluates each event against every loaded scenario Filter expression. Matching events are poured into the appropriate bucket partition.
  Evidence: pkg/leakybucket/manager_run.go:212-248 [Confirmed]

- When a bucket overflows (capacity exceeded), an alert is generated. The Processor interface defines OnBucketPour, OnBucketOverflow, and AfterBucketPour hooks.
  Evidence: pkg/leakybucket/processor.go:8-12 [Confirmed]

- Bucket types include LeakyType, TriggerProcessor, ConditionalProcessor, BayesianProcessor, and UniqProcessor.
  Evidence: pkg/leakybucket/buckettype.go, trigger.go, conditional.go, bayesian.go, uniq.go [Confirmed]

---

## Alerts

- The Alert entity has fields: scenario, sourceIp, sourceRange, sourceCountry, sourceAsNumber/Name, sourceLatitude/Longitude, eventsCount, startedAt, stoppedAt, capacity, leakSpeed, simulated, uuid, remediation, kind, bucketId, message. Most are immutable.
  Evidence: pkg/database/ent/schema/alert.go:17-55 [Confirmed]

- Alert has edges (one-to-many) to Decision, Event, and Meta, all with ON DELETE CASCADE.
  Evidence: pkg/database/ent/schema/alert.go:59-76 [Confirmed]

- Alert has a many-to-one edge to Machine ("owner").
  Evidence: pkg/database/ent/schema/alert.go:61-63 [Confirmed]

- Alert has indexes on id, uuid, and scenario.
  Evidence: pkg/database/ent/schema/alert.go:79-85 [Confirmed]

- Alerts are created by agents POSTing to /v1/alerts (JWT-authenticated).
  Evidence: pkg/apiserver/controllers/controller.go:125 [Confirmed]

---

## Decisions

- The Decision entity has fields: until (Time, nillable, optional — the expiry timestamp), scenario, type, scope, value, origin, start_ip, end_ip, start_suffix, end_suffix, ip_size, simulated, uuid, alert_decisions (FK).
  Evidence: pkg/database/ent/schema/decision.go:17-41 [Confirmed]

- Decision has an edge back to Alert via edge.From("owner", Alert.Type).Ref("decisions").
  Evidence: pkg/database/ent/schema/decision.go:45-51 [Confirmed]

- Decision indexes: (start_ip, end_ip), (value, type, scope, until, simulated), (until), (alert_decisions).
  Evidence: pkg/database/ent/schema/decision.go:54-61 [Confirmed]

- Decisions are created as part of an Alert (embedded in the POST /v1/alerts payload), not via a separate endpoint.
  Evidence: pkg/apiserver/controllers/v1/alerts.go:150 [Confirmed]

---

## Decision Expiry

- Decision expiry is handled at query time: when decisions are queried, a WHERE until > now() filter excludes expired decisions. There is no background job that flips a status flag.
  Evidence: pkg/database/decisions.go:33 [Confirmed]

- FormatDecisions computes remaining duration as Until.Sub(time.Now().UTC()) for bouncer consumption.
  Evidence: pkg/apiserver/controllers/v1/decisions.go:23 [Confirmed]

- A periodic flush scheduler (flushInterval = 1 minute) deletes old expired decisions and orphan alerts from the database. This is cleanup, not the enforcement expiry mechanism.
  Evidence: pkg/database/flush.go:32, line 40 [Confirmed]

---

## Bouncers / Enforcement

- Bouncers authenticate to LAPI via API key and poll GET /v1/decisions or GET /v1/decisions/stream for active decisions.
  Evidence: pkg/apiserver/controllers/controller.go:146-149 [Confirmed]

- The Bouncer entity has fields: name (unique, immutable), api_key (sensitive), revoked, ip_address, type, version, last_pull, stream_cursor, auth_type, auto_created, and OS fields.
  Evidence: pkg/database/ent/schema/bouncer.go:17-44 [Confirmed]

- Bouncer entity has no edges (no FK relationships to other entities).
  Evidence: pkg/database/ent/schema/bouncer.go:48-50 [Confirmed]

- The stream_cursor field tracks the highest decision ID already streamed, used as a safe cursor instead of wall-clock timestamps.
  Evidence: pkg/database/ent/schema/bouncer.go:33-36 [Confirmed]

---

## Database / Data Model

- Six core entities: Alert, Decision, Event, Meta, Machine, Bouncer.
  Evidence: pkg/database/ent/schema/ directory [Confirmed]

- Additional entities: Allowlist, AllowlistItem, Config, Lock, Metric.
  Evidence: pkg/database/ent/schema/ directory [Confirmed]

- Machine has fields: machineId (unique, immutable), password (sensitive), ipAddress, scenarios, version, isValidated (default false), auth_type, OS fields, hubstate (JSON), datasources (JSON).
  Evidence: pkg/database/ent/schema/machine.go:25-54 [Confirmed]

- Machine has a one-to-many edge to Alert.
  Evidence: pkg/database/ent/schema/machine.go:58-61 [Confirmed]

- Meta has fields: key, value (max 4095 chars), and FK to Alert via alert_metas.
  Evidence: pkg/database/ent/schema/meta.go:16-26 [Confirmed]

---

## API

- Routes are registered in pkg/apiserver/controllers/controller.go.
  Evidence: pkg/apiserver/controllers/controller.go:117-156 [Confirmed]

- Machine (agent) routes (JWT-authenticated):
  - POST /v1/watchers — register machine
  - POST /v1/watchers/login — login
  - GET /v1/refresh_token — refresh JWT
  - POST /v1/alerts — create alert with decisions
  - GET /v1/alerts — list alerts
  - GET /v1/alerts/:alert_id — get single alert
  - DELETE /v1/alerts/:alert_id — delete alert
  - DELETE /v1/alerts — bulk delete alerts
  - DELETE /v1/decisions — delete decisions
  - DELETE /v1/decisions/:decision_id — delete single decision
  - GET /v1/heartbeat — heartbeat
  Evidence: pkg/apiserver/controllers/controller.go:118-141 [Confirmed]

- Bouncer routes (API-key-authenticated):
  - GET /v1/decisions — query active decisions
  - GET /v1/decisions/stream — stream new/expired decisions
  Evidence: pkg/apiserver/controllers/controller.go:146-149 [Confirmed]

- Health endpoint: GET /health (unauthenticated).
  Evidence: pkg/apiserver/controllers/controller.go:99 [Confirmed]

---

## CLI

- cscli is the admin CLI tool, built from cmd/crowdsec-cli/.
  Evidence: cmd/crowdsec-cli/ directory [Confirmed]

---

## Gaps

- Decision expiry is query-time only (WHERE until > now()). There is no proactive push to bouncers when a decision expires. A bouncer only learns of expiry at its next poll.
  Evidence: pkg/database/decisions.go:33, pkg/apiserver/controllers/v1/decisions.go:23 [Confirmed]

- The v2 API group in controller.go is entirely commented out and non-functional.
  Evidence: pkg/apiserver/controllers/controller.go:161-193 [Confirmed]

- No rate limiting on the POST /v1/watchers registration endpoint; body size limits exist but no per-IP throttle.
  Evidence: pkg/apiserver/controllers/controller.go:118 [Likely]

- Bouncer entity has no edge to decisions or alerts — no database-level record of which decisions a bouncer has seen. The stream_cursor field partially addresses this.
  Evidence: pkg/database/ent/schema/bouncer.go:48-50 [Confirmed]
