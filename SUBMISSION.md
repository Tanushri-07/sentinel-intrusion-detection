# HackBack Submission — Sentinel Intrusion Detection

---

## Team Information
- **Team**: DBG-831
- **Repository**: Sentinel Intrusion Detection
- **Corpus / Study Target**: CrowdSec (`crowdsecurity/crowdsec`)

---

## HackBack Problem & Target System

- **Original Repository Studied**: CrowdSec (`crowdsecurity/crowdsec`)
- **Verified Commit Studied**: `7a73b1615a931aa42b1f165b064cc4be3106ce32` (Mon Oct 5 2026)
- **Problem Context**:
  During result week, a university portal is overwhelmed by bot-driven brute-force password guessing attacks. Legitimate students face degraded service or locked access. The goal is to build a focused, reliable intrusion prevention system protecting the portal in real time with exact ban expiration and clean observability.

---

## The Two Improvements

### 1. Gap Fix: Exact Request-Time Ban Expiry via Blocker Middleware
- **Original CrowdSec Limitation**:
  In CrowdSec, decision expiry relies solely on query-time filtering (`WHERE until > now()`, verified at `pkg/database/decisions.go:33`). External bouncers poll LAPI periodically (e.g. every 10–30s). Consequently, expired bans linger at the enforcement layer until the bouncer's next polling cycle.
- **Sentinel's Fix**:
  Sentinel integrates a **Blocker ASGI middleware** positioned directly in front of the application routes. On **every single incoming HTTP request**, the middleware evaluates `WHERE value = :ip AND type = 'ban' AND until > :now`.
  - Ban expiry is **exact to the millisecond**: the very first request arriving at $t > until$ immediately passes through.
  - The background **Expiry Sweeper** is decoupled from access control; it only cleans up expired records from SQLite for database hygiene.

### 2. Differentiator: Optional AI-Powered Threat Explanation
- **What Original CrowdSec Lacks**:
  CrowdSec provides structured alerts containing scenario names and IP metadata, but offers no human-readable natural language synthesis explaining the context or threat narrative.
- **Sentinel's Innovation**:
  Sentinel includes an optional **AI Threat Explainer** module. When an `AI_API_KEY` is configured in `.env`, the explainer synthesizes attack patterns (e.g., distinguishing high-speed bot dictionary sweeps from human typos) into plain-English summaries stored in `alert.ai_explanation` and exposed via `/v1/alerts`.
  - **Graceful degradation**: The entire detection, blocking, and unblocking pipeline functions with 100% feature completeness if no AI key is provided.
  - **No secrets in documentation**: All secrets are managed via local `.env`.

---

## Clean-Room Declaration

This project is a clean-room reimplementation inspired by architectural concepts of CrowdSec (log tailing, pipeline separation, sliding windows, and `until` decision records) but contains **no copied source code** from CrowdSec.
- All code is implemented in Python 3.11+ using FastAPI, SQLite, and pytest.
- All schemas, middleware, and detection logic were written from scratch based exclusively on verified specifications in `docs/`.
