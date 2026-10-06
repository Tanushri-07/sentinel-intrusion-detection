# HACKBACK code review · DBG-831 · Intrusion Detection & Auto-ban
- Reviewed at: 2026-10-06T08:53:40Z (2026-10-06T14:23:40+05:30 IST)
- Judged commit: 8e942349b350b592e47b4e61c87ae886255e6e4a (2026-10-06T13:02:06+05:30) · the last commit before the code freeze
- Reviewer: AI agent run by a HACKBACK judge

---

## Step 0 — What was judged

```
git log -1:                8e94234 2026-10-06T13:02:06+05:30
First 5 commits:
  e97ef41 2026-10-05T21:51:40+05:30 docs: add rebuild documentation
  fee2014 2026-10-05T22:15:14+05:30 docs: add HackBack submission artifacts
  2586e77 2026-10-05T22:43:37+05:30 Update SUBMISSION.md
  929435e 2026-10-05T22:46:25+05:30 docs: lock stack, demo portal, exact expiry, client IP, Given/When/Then
  93012d4 2026-10-05T22:50:30+05:30 docs: Given/When/Then criteria, two-IP demo
First docs commit:         e97ef41 2026-10-05T21:51:40+05:30
First code commit:         fee2014 2026-10-05T22:15:14+05:30
Post-freeze commits:       (none)
```

---

## Step 1 — Feature Map

| Feature | Works E2E? | Evidence |
|---|---|---|
| Demo portal `POST /login` with seeded creds | ✅ | app/portal.py:39-52, tested at tests/test_portal_and_detector.py:26-28 |
| Structured auth log (`portal_auth.log`) | ✅ | app/portal.py:27-37 |
| Log watcher (tail with inode/truncation handling) | ✅ | app/watcher.py:49-82 |
| Log parser (validates 4-part format, discards malformed) | ✅ | app/watcher.py:17-47 |
| Sliding window brute-force detector | ✅ | app/detector.py:12-123, deque per IP at :14-15, window pruning at :58-61 |
| Alert + Decision creation in SQLite | ✅ | app/detector.py:77-104 |
| Blocker ASGI middleware (`until > now` per request) | ✅ | app/middleware.py:8-46 |
| Expiry sweeper (background cleanup) | ✅ | app/sweeper.py:8-45 |
| Admin API (list/check/create/delete decisions, list alerts, explain) | ✅ | app/admin.py:40-164, all routes authenticated via `X-Api-Key` |
| AI threat explainer (optional, async) | ✅ graceful fallback | app/ai.py:9-51, tested disabled at tests/test_ai_explainer.py:9-40 |
| Health endpoint (public) | ✅ | app/main.py:35-37 |
| Username pipe-char validation | ✅ | app/portal.py:20-25 |
| TRUST_PROXY IP resolution | ✅ | app/ip_utils.py:4-13 |

**Mocked / hard-coded / TODO**: None found. The AI explainer calls an external API (Groq) but is genuinely optional and the disabled path is tested. Seeded demo users are intentional (demo portal).

---

## Step 2 — Scorecard

### DBG-831 · Intrusion Detection & Auto-ban
Commit: 8e94234 · 2026-10-06T13:02:06+05:30 · Clean-room: OK

| Section | Score | Why (path:line) |
|---|---|---|
| A. Core flow | 28/30 | Full pipeline works: portal writes log → watcher tails → parser extracts events → detector sliding window → alert + decision in SQLite → blocker middleware enforces 403. Proven by 8/8 passing tests. Deducted 2: log watcher polls at 100ms (`app/watcher.py:99`) rather than using OS-level inotify/kqueue, and successful logins are still stored as events in the DB and counted through the parser (though not counted by the detector towards the ban threshold, `app/detector.py:39-40`). |
| B. Killer Tests | 28/30 | See breakdown below. |
| C. Two improvements | 16/20 | See breakdown below. |
| D. Built from their docs | 9/10 | PRD M1–M9 all implemented. API routes match `docs/API.md` exactly. DATA_MODEL schema matches `app/db.py:36-93` tables, columns, indexes, and FK constraints. Minor drift: PRD specifies `401` body as `{"status":"fail","detail":"..."}` but code wraps it in HTTPException `detail` dict (`app/portal.py:49-52`), producing `{"detail":{"status":"fail","detail":"..."}}` — a nested envelope. |
| E. Engineering | 7/10 | See breakdown below. |
| **Total** | **88/100** | |

---

### Killer Tests

1. **READY · 10/10** — 10 failed logins from one IP within a minute get that IP banned.
   - Sliding window per IP using `deque` with time-based pruning (`app/detector.py:58-63`). Only `failed_login` events counted (`app/detector.py:39-40`). Threshold and window configurable via `settings.BAN_THRESHOLD` / `settings.WINDOW_SECONDS` (`app/config.py:11-12`). Ban created with `until` (`app/detector.py:73-74`). Test `tests/test_killer_1_brute_force.py` sends 10 failures, verifies alert/decision in DB, and confirms 11th request returns 403. Test passes.

2. **READY · 10/10** — A normal user logging in at the same time is not affected.
   - Bans keyed by IP (`app/detector.py:59`, `app/middleware.py:21-31` — `WHERE value = ?`). Successful logins skip ban logic (`app/detector.py:39-40`). Test `tests/test_killer_2_bystander_isolation.py` bans attacker IP `198.51.100.10`, then verifies innocent IP `203.0.113.50` gets `200 OK` while attacker stays at `403`. Test passes. No explicit allowlist, but bans are per-IP and successes are not counted — requirement met.

3. **PARTIAL · 8/10** — The ban is lifted exactly when it expires.
   - Each decision stores `until` (`app/detector.py:74`). Blocker checks `until > now` on every request (`app/middleware.py:23-26`). No dependency on sweeper for enforcement. Test `tests/test_killer_3_exact_expiry.py` sets `BAN_DURATION_SECONDS=2`, triggers ban, sleeps 2.1s, and confirms request passes. Test passes. **Deducted 2**: Timestamps use second-level precision only (`strftime("%Y-%m-%dT%H:%M:%SZ")` at `app/middleware.py:15`, `app/detector.py:74`) — the docs claim "exact to the millisecond" but the implementation can only resolve to the nearest second. Additionally, the middleware opens and closes a new SQLite connection on every single request (`app/middleware.py:20-31` via `get_db()`), which could be a performance concern under high load but functionally works.

---

### Improvements

1. **Exact request-time ban expiry via Blocker middleware · 9/10**
   - **Claimed in**: `docs/GAPS.md` Improvement 1, `SUBMISSION.md` §Two Improvements §1.
   - **Evidence**: Blocker middleware at `app/middleware.py:8-46` queries `until > :now` on every request. Sweeper at `app/sweeper.py:13-29` only does cleanup (`SET active = 0`). KT3 test proves expiry works without sweeper (`tests/test_killer_3_exact_expiry.py:36-44`).
   - **Deducted 1**: The claim is "exact to the millisecond" but timestamps are second-level (`%Y-%m-%dT%H:%M:%SZ`), so granularity is ≤1 second, not millisecond. Still a genuine and meaningful improvement over CrowdSec's polling approach.

2. **AI-powered threat explanation · 7/10**
   - **Claimed in**: `docs/GAPS.md` Improvement 2, `SUBMISSION.md` §Two Improvements §2.
   - **Evidence**: `app/ai.py:9-51` implements async Groq API call with 5s timeout, zero retries, non-secret payload. Graceful degradation when `AI_API_KEY=""` (`app/ai.py:10-12`). Admin visibility via `GET /v1/alerts/{id}/explain` (`app/admin.py:143-164`). Disabled-path test passes (`tests/test_ai_explainer.py`).
   - **Deducted 3**: The enabled path (actual API call) is never tested — no mock/stub test proves the happy path works. The feature calls an external service that cannot be verified locally. Feature is genuinely wired in and the code is sound, but "fully built and wired in" is hard to confirm without a working test of the success path.

---

### E. Engineering Detail (7/10)

| Aspect | Status | Evidence |
|---|---|---|
| Input validation on login | ✅ | Pydantic model + pipe-char validator (`app/portal.py:16-25`) |
| Admin route auth | ✅ | `verify_admin_key` on every `/v1/*` route (`app/admin.py:11-17`) |
| Manual decision IP validation | ✅ | `ipaddress.ip_address()` validator (`app/admin.py:24-31`) |
| Error handling in watcher/sweeper | ✅ | try/except with logging (`app/watcher.py:81-82`, `app/sweeper.py:30-31`) |
| Malformed log lines | ✅ | Parser validates 4 parts and field prefixes (`app/watcher.py:22-38`) |
| No committed secrets | ✅ | `.env` in `.gitignore`, only `.env.example` committed |
| README steps run | ✅ | Verified: venv → pip install → uvicorn → pytest all work |
| ADMIN_API_KEY default | ⚠️ | Hardcoded default `"sentinel-admin-secret-key"` in `app/config.py:16`. If user doesn't set `.env`, admin endpoints are "protected" by a publicly known string. `.env.example` shows `ADMIN_API_KEY=` (blank), but `config.py` ignores that. |
| Client IP spoofing | ⚠️ | When `TRUST_PROXY=true`, any client can send `X-Forwarded-For` to spoof their IP (`app/ip_utils.py:5-10`). No verification that the connecting IP is actually a trusted proxy. Default is `false` (safe), but the demo scripts and tests all run with `true`. |
| DB connection per request | ⚠️ | Middleware opens+closes a new SQLite connection on every request (`app/middleware.py:20`). Works but no connection pooling. |

Deducted 3 for: hardcoded admin key default (-1), no trusted-proxy-IP verification when TRUST_PROXY=true (-1), no connection pooling strategy (-1).

---

## Step 3 — Flags

**Flags: none.**

- **Clean-room**: OK. Docs committed Oct 5 (21:51–23:28 IST), code committed Oct 6 (13:02 IST). No commits before Oct 5 16:00 IST. No commits after freeze (Oct 6 13:30 IST). No CrowdSec license headers, identifiers, or Go code. Python-only codebase with completely different architecture (single-process FastAPI vs CrowdSec's multi-process Go).
- **Committed secrets**: None. `.env` is gitignored. Only `.env.example` committed with blank secret fields.
- **Fake features**: None. All features work end to end. AI explainer is honestly optional and the disabled path is tested.

---

## 3 Questions for the Defence

1. **`ADMIN_API_KEY` default**: `app/config.py:16` defaults to `"sentinel-admin-secret-key"`. If a production deployment forgets to set `.env`, every admin endpoint is accessible with this publicly known key. Why not fail-safe (refuse to start if the key is blank or default)?

2. **Second-level timestamp precision**: The docs and SUBMISSION.md claim "exact to the millisecond" ban expiry, but `strftime("%Y-%m-%dT%H:%M:%SZ")` at `app/middleware.py:15` and `app/detector.py:74` truncates to whole seconds. Can you demonstrate sub-second accuracy, or should the claim be corrected?

3. **AI explainer happy-path test**: `tests/test_ai_explainer.py` only tests the disabled path (`AI_API_KEY=""`). How would you prove the enabled path works without calling the real Groq API — e.g., with `httpx`-level mocking or a recorded response fixture?

---

SCORE core=28 kt=28 imp=16 docs=9 eng=7 total=88
