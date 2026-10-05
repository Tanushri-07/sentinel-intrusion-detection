# Gaps — CrowdSec Analysis & Sentinel Improvements

---

## Verified Gaps in the Original CrowdSec System

### Gap 1: Query-Time-Only Decision Expiry

| Property | Detail |
|---|---|
| **Gap** | Decision expiry is enforced only at query time via a WHERE until > now() filter. There is no proactive mechanism to notify bouncers when a decision expires. A bouncer only discovers a decision has expired on its next poll. |
| **Type** | Correctness / UX |
| **Evidence** | pkg/database/decisions.go:33 — `decision.UntilGT(now)` [Confirmed]. pkg/apiserver/controllers/v1/decisions.go:23 — remaining duration computed as Until.Sub(time.Now().UTC()) [Confirmed]. No background expiry job that pushes notifications was found. |
| **Who it hurts** | End users whose IPs are banned. If a bouncer polls every 30 seconds, a ban could persist up to 30 seconds past its intended expiry. |
| **Suggested fix** | Add a proactive expiry sweeper that marks decisions as inactive and, if possible, pushes unblock notifications to the enforcement layer. |
| **Severity** | Medium |

### Gap 2: Commented-Out v2 API

| Property | Detail |
|---|---|
| **Gap** | The entire v2 API route group is commented out and non-functional. |
| **Type** | Docs drift / Dead code |
| **Evidence** | pkg/apiserver/controllers/controller.go:161-193 — entire block wrapped in `/* ... */` [Confirmed] |
| **Who it hurts** | Maintainers who may expect v2 to be available. |
| **Suggested fix** | Remove the dead code or implement it. |
| **Severity** | Low |

### Gap 3: No Rate Limiting on Machine Registration

| Property | Detail |
|---|---|
| **Gap** | The POST /v1/watchers endpoint (machine registration) has a body size limit but no per-IP rate limiting. An attacker could rapidly create many machine registrations. |
| **Type** | Security |
| **Evidence** | pkg/apiserver/controllers/controller.go:118 — only `unauthBodyLimit` middleware is applied, no rate limiter [Likely] |
| **Who it hurts** | LAPI operators; could be used for resource exhaustion. |
| **Suggested fix** | Add per-IP rate limiting on unauthenticated endpoints. |
| **Severity** | Medium |

### Gap 4: No Bouncer-to-Decision Relationship in Database

| Property | Detail |
|---|---|
| **Gap** | The Bouncer entity has no edge to Decision or Alert. There is no database-level audit trail of which decisions a specific bouncer has received or is enforcing. The stream_cursor field partially tracks position but not per-decision acknowledgment. |
| **Type** | Data / Observability |
| **Evidence** | pkg/database/ent/schema/bouncer.go:48-50 — `Edges() returns nil` [Confirmed]. Stream cursor at bouncer.go:36 [Confirmed]. |
| **Who it hurts** | Operators trying to debug enforcement issues (e.g., "did my bouncer actually receive this decision?"). |
| **Suggested fix** | Add an audit log or join table tracking bouncer-decision delivery. |
| **Severity** | Low |

---

## Selected Improvements for Our Rebuild

### Improvement 1: Gap Fix — Proactive Decision Expiry (from Gap 1)

**What we fix**: CrowdSec's query-time-only expiry means bans can persist past their intended expiration until the next bouncer poll.

**How Sentinel fixes it**: Sentinel adds an Expiry Sweeper — a background task that runs every few seconds, finds decisions whose `until` timestamp has passed, marks them as `active = false`, and notifies the Blocker to stop enforcement immediately. Additionally, the Blocker itself always checks `until > now()` on every request for defense in depth.

**Why it matters**: For the university portal, students should be unblocked exactly when their ban expires. A 30-second delay is unacceptable during result week when thousands of students are trying to access their results.

**How it will be demonstrated**: Killer Test 3 — set a ban with a short duration (e.g., 10 seconds), verify that requests are blocked during the ban, and verify that requests succeed immediately after the expiration timestamp (within 1 second, not 30).

---

### Improvement 2: Differentiator — AI-Powered Threat Explanation

**What the original does not have**: CrowdSec provides alerts with scenario names and source IPs, but no AI-generated, human-readable explanation of what happened and why it is suspicious. The alert data is structured but requires technical knowledge to interpret.

**What Sentinel adds**: When an AI API key is configured in `.env`, Sentinel calls an LLM (e.g., OpenAI or Gemini) to generate a plain-English explanation of each detected attack. The explanation is stored with the alert and available via the Admin API.

Example output:
> "This alert detected a brute-force login attack from IP 192.168.1.100. The attacker attempted 10 different passwords for user 'student_2024' within 45 seconds. This pattern is consistent with automated credential-stuffing, likely from a bot. The IP has been banned for 4 hours."

**Why it matters to the university portal user**: University IT administrators may not be security experts. During the stress of result week, a clear explanation helps them understand what happened, confirm the ban is appropriate, and decide whether to escalate (e.g., report the IP to the ISP).

**How it will be demonstrated**:
1. Start Sentinel with AI key in .env.
2. Trigger a brute-force scenario.
3. Call GET /v1/alerts/:id/explain and see the AI explanation.
4. Start Sentinel without the AI key.
5. Verify the system detects and bans correctly; the explanation field is null.

---

## Summary

| # | Improvement | Source |
|---|---|---|
| 1 | Proactive decision expiry via Expiry Sweeper | Gap Fix (Gap 1) |
| 2 | AI-powered threat explanation | Differentiator (new feature) |
