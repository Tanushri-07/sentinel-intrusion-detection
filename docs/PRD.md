# Product Requirements Document — Sentinel Intrusion Detection

---

## 1. Problem

During result week, the university portal is overwhelmed by bots guessing student passwords. These brute-force attacks degrade service for legitimate students trying to access their results. The university has no automated system to detect and block attacking IPs in real time.

---

## 2. Target User

University IT administrators responsible for keeping the student result portal available and secure during high-traffic periods.

---

## 3. Problem Statement

"For university IT administrators who struggle with bot-driven brute-force attacks during result week, Sentinel Intrusion Detection automatically reads server logs, detects attack patterns, and bans attacking IPs with precise automatic expiry, unlike CrowdSec which relies on query-time-only expiry with no proactive unblock notification and offers no AI-powered threat explanation."

---

## 4. Core Flow

1. The university portal web server writes authentication logs (including failed logins) to a log file.
2. Sentinel's **Log Watcher** tails the log file and emits raw log lines.
3. The **Log Parser** transforms each raw line into a structured event (timestamp, IP, event type, username, etc.).
4. The **Attack Detector** receives parsed events and maintains per-IP sliding time windows. It evaluates configured scenarios (e.g., "10 failed logins from one IP in 60 seconds").
5. When a scenario threshold is exceeded, the detector creates an **Alert** and a **Ban Decision** with a defined duration.
6. The decision is stored in the database with an exact expiration timestamp.
7. The **Blocker** component enforces active bans. It checks the decision store before allowing or rejecting requests.
8. When a decision's expiration time is reached, the Blocker stops blocking that IP. The system proactively removes or invalidates the enforcement.
9. An optional **AI Threat Explainer** (when configured with an API key in .env) provides human-readable explanations of detected attack patterns. The system runs fully without this key.

---

## 5. Features (MoSCoW)

### Must Have

- **M1**: Tail and read server log files in real time.
- **M2**: Parse log lines into structured events with at minimum: timestamp, source IP, event type (e.g., failed_login), username.
- **M3**: Configurable brute-force detection scenario: N failed logins from one IP within T seconds triggers a ban.
- **M4**: Store ban decisions with exact expiration timestamps.
- **M5**: Enforce bans — blocked IPs cannot access the portal while the ban is active.
- **M6**: Automatic unblock — the ban is lifted exactly when it expires, not on the next poll cycle.
- **M7**: Isolation — a ban on one IP does not affect any other IP.
- **M8**: Admin visibility — an admin can view current alerts and active bans.

### Should Have

- **S1**: AI-powered threat explanation that describes detected attacks in plain English (requires API key in .env; system works without it).
- **S2**: Admin API or CLI to manually add/remove bans.
- **S3**: Configurable ban duration.
- **S4**: Logging of all detection and enforcement events for audit.

### Could Have

- **C1**: Dashboard web UI for viewing alerts and bans.
- **C2**: Support for multiple log formats.
- **C3**: Email or webhook notifications on new bans.

### Won't Have

- **W1**: Community/crowd-sourced threat intelligence (CrowdSec CAPI equivalent).
- **W2**: Multi-machine agent coordination.
- **W3**: Support for non-IP scope (ranges, ASNs, etc.).
- **W4**: WAF or application-level security rules.

---

## 6. Out of Scope

- Modifying the university portal application itself.
- Replacing the web server or proxy.
- GeoIP enrichment.
- Container or cloud-native deployment orchestration.
- TLS mutual authentication between components.

---

## 7. Acceptance Criteria

### Killer Test 1 — Brute-Force Detection

**Given** one IP generates 10 failed login events within one minute,
**When** the tenth failed login is processed,
**Then** that IP is banned.

### Killer Test 2 — Innocent Bystander Isolation

**Given** an attacker IP is generating failed logins while a normal user is logging in from another IP,
**When** the attack threshold is reached,
**Then** only the attacking IP is banned and the normal user's IP remains unaffected.

### Killer Test 3 — Exact Expiry

**Given** an IP has an active ban with a defined expiration,
**When** the exact expiration time is reached,
**Then** the IP is no longer blocked.

### AI Explainer Availability

**Given** the AI API key is not set in .env,
**When** the system starts,
**Then** the system runs normally; AI explanations are absent but all detection, banning, and unblocking work correctly.

### AI Explainer Functionality

**Given** the AI API key is set in .env,
**When** a new alert is created,
**Then** the system generates a human-readable explanation of the attack pattern associated with the alert.

### Admin Visibility

**Given** there are active bans and past alerts,
**When** an admin queries the system (via API or CLI),
**Then** the admin sees a list of active bans with IP, reason, and expiration, and a list of alerts with scenario and source IP.
