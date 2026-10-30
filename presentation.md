# AI-SOC: Autonomous Cyber Defense, Threat Intelligence & Ingestion Platform
## Comprehensive Architecture, Features, Operational Workflows & Roadmap Presentation

---

## 1. Executive Summary & Vision

**AI-SOC** is an enterprise-grade Security Operations Center (SOC) web platform architected to bridge the gap between autonomous threat detection and safe, verifiable incident response. 

Traditional SOC environments suffer from analyst fatigue, alert floods from SIEM tools, and slow incident triage. Conversely, purely autonomous response systems introduce catastrophic risks of service disruption or unvetted privilege escalation.

AI-SOC solves this with a **Dual-Plane Defense Architecture**:
1. **Autonomous Intelligence Plane**: Powered by local open-source LLMs (via Ollama, with Gemini fallback and deterministic heuristic failover) that ingest, correlate, and analyze high-velocity SIEM logs, backend call traces, and attack telemetry in real time.
2. **Deterministic Safety & Governance Plane**: Enforces an 8-Tier Risk Ladder (L0 to L7), strict deterministic policies (P001–P005), dual-operator cryptographic approvals, and an immutable NIST SP 800-92 compliant SHA-256 cryptographic audit chain.

---

## 2. Core Architecture & System Design

```
+-----------------------------------------------------------------------------------+
|                                  USER / ANALYST                                   |
|                Role-Based Access Control: Analyst | Approver | Admin              |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        FRONTEND PRESENTATION LAYER (Vite + React)                 |
|  - Real-Time Command Dashboard             - AI Ollama Diagnostic Console         |
|  - Wazuh SIEM Ingestion & Attack Replay    - L0-L7 Autonomous Safety Gate         |
|  - Multi-Party Approval Inbox              - Cryptographic Audit Ledger           |
|  - Investigation Triage & Case Notes       - Automated Security Test Matrix       |
|  - API Key & SIEM Endpoint Management      - Quick 1-Click Role Switcher          |
+-----------------------------------------------------------------------------------+
                                          | REST API (Bearer Token / HMAC API Key)
                                          v
+-----------------------------------------------------------------------------------+
|                        EXPRESS APPLICATION LAYER (server.ts / app.ts)             |
|  - Security Headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)   |
|  - In-Memory Sliding-Window Rate Limiter & Brute-Force Lockout Defense            |
|  - Live Backend Call & Error Telemetry Tracker (Sanitizing Passwords / Keys)      |
+-----------------------------------------------------------------------------------+
            |                                           |
            v                                           v
+----------------------------------+     +------------------------------------------+
|      AI & TRIAGE ENGINE          |     |           SAFETY & COMPLIANCE            |
| - Ollama Live Open-Source Models |     | - L0-L7 Risk Ladder                      |
|   (llama3, mistral, etc.)        |     | - Deterministic Policies (P001-P005)     |
| - Gemini 2.5 Flash Fallback      |     | - Four-Eyes Principle Approval Engine    |
| - High-Precision Heuristic Rules |     | - NIST SP 800-92 SHA-256 Hash Chain      |
| - MITRE ATT&CK Mapping & Command |     | - Tamper Detection & Integrity Verifier  |
+----------------------------------+     +------------------------------------------+
```

---

## 3. Detailed Walkthrough of Platform Features

### 3.1. Role-Based Access Control (RBAC) & Session Defense
* **Three Defined Operator Roles**:
  * **ANALYST**: Read telemetry, view SIEM alerts, launch attack simulations, query AI diagnostics, create triage notes, and request remediation actions. Cannot execute high-risk actions autonomously.
  * **APPROVER**: Authorized to review pending L4–L7 intervention requests, inspect parameter hashes, and sign off or reject operational changes.
  * **ADMIN**: Full platform administration, API key provisioning/revocation, security suite execution, ledger tamper tests, and policy management.
* **Brute-Force Lockout (Policy P001)**:
  * Strict limit of 5 consecutive failed authentication attempts.
  * Triggers an automated 300-second lockout and returns HTTP 429.
  * Includes manual lockout reset and quick 1-click test credential login.

### 3.2. Real-Time Command Dashboard
* **Dynamic Security Posture Overview**: Displays real-time counts for active alerts, pending four-eyes approvals, overall threat level, audit ledger blocks, and autonomous mitigation stats.
* **Interactive Attack Scenarios**: Pre-configured real-world attack replays (e.g., Domain Controller Kerberoasting, SSH Dictionary Sweep, API Credential Stuffing, Ransomware Volume Shadow Wipe) that inject telemetry and verify SOC responses.
* **Live System Metrics**: CPU load, memory utilization, SIEM ingestion rate, and active agent connectivity.

### 3.3. Wazuh SIEM Ingestion & Attack Drill Simulator
* **Syslog / JSON Ingestion Engine**: Live ingestion endpoint (`/api/wazuh/ingest`) supporting API key authentication for external Wazuh agents and Windows Event Forwarders.
* **Automated Severity Mapping**: Translates raw Wazuh rule levels (1–16) into standard SOC severities:
  * Low (1–4), Medium (5–7), High (8–11), Critical (12–16).
* **One-Click Attack Drill Replay**: Allows SOC operators to execute drills across multiple attack vectors:
  * Windows Active Directory brute-force attacks.
  * Linux SSH credential stuffing with IP spoofing.
  * Web Application SQLi / RCE attempts.
  * Ransomware canary token triggers.

### 3.4. Ollama & Backend Diagnostic Engine
* **Local Free-Model AI Triage**: Directly interfaces with local Ollama daemon (`http://127.0.0.1:11434`), supporting local models such as `llama3`, `mistral`, or custom cybersecurity fine-tunes.
* **Three-Tier Intelligent Fallback**:
  1. Primary: Local Ollama daemon.
  2. Standby Cloud AI: Gemini 2.5 Flash API via `@google/genai`.
  3. Fail-Safe: Built-in deterministic heuristic SOC engine (guarantees zero downtime even during total network failure).
* **Automatic Backend Error & API Call Profiler**:
  * Captures all incoming HTTP API calls, status codes, latency, caller IP, and sanitized payload snippets.
  * Automatically isolates HTTP 401, 403, 429, and 500 error events for one-click deep AI root-cause analysis, MITRE ATT&CK technique mapping, and remediation script generation.

### 3.5. Autonomous L0–L7 Safety Gate & Policy Enforcement
To prevent rogue AI actions or accidental operational outages, every single action passes through the **Deterministic Safety Gate**:
* **L0 — Observe**: Passive telemetry logging and baseline metric collection.
* **L1 — Enrich**: Threat intelligence IP lookup and WHOIS correlation.
* **L2 — Rate Limit**: Temporary request throttling at edge reverse proxies.
* **L3 — Quarantine**: Host isolation in non-critical subnets (Auto-executable up to L3).
* **L4 — Isolate**: Disabling switch ports or domain account suspension (Requires 1 Approver).
* **L5 — Terminate**: Killing core production processes (Requires Human Approval).
* **L6 — Contain**: Segmenting critical internal networks / VLAN detachment (Requires Senior Approver).
* **L7 — Lockdown**: Enterprise-wide network lockdown & Active Directory freeze (Dual Approver Required).

#### Deterministic Policies Enforced:
* **P001**: 5 failed logins within 60 seconds triggers a mandatory 300-second lockout.
* **P002**: Critical infrastructure hosts (`WIN-DC-01`, `PROD-DB-CLUSTER`) can **never** be auto-isolated without human approval.
* **P003**: Remediation scripts containing destructive payloads (`rm -rf`, `format`, `drop database`) are strictly blocked at parse time.
* **P004**: Actions requested at L4 or above enforce a cryptographic Four-Eyes sign-off.
* **P005**: All actions and approvals must produce an immutable cryptographic audit record before execution.

### 3.6. Four-Eyes Principle Approval Inbox
* Enforces separation of duties: The analyst proposing an action **cannot** approve their own request.
* Displays detailed parameter hashes, risk assessment, impacted endpoints, and countdown timers.
* Allows designated Approvers and Admins to approve or reject with mandatory justification notes.

### 3.7. Cryptographic NIST SP 800-92 Audit Chain
* Every event (logins, policy triggers, AI triage queries, approvals, key creations) is hashed into a SHA-256 block linking to the previous block's hash:
  $$\text{Current Hash} = \text{SHA256}(\text{Index} + \text{Timestamp} + \text{Actor} + \text{Action} + \text{Payload} + \text{Previous Hash})$$
* **Built-in Tamper Detection Engine**: Operators can trigger an intentional byte-level tamper simulation to verify that the integrity verifier immediately detects ledger tampering, flags the compromised block index, and alerts the SOC team.

### 3.8. Automated Security Test Matrix
* Runs a suite of 9 rigorous automated platform tests:
  1. PBKDF2 Password Salt & Hash Verification.
  2. Brute-Force Rate Limiting & Lockout Trigger (P001).
  3. RBAC Analyst Endpoint Authorization Enforcement.
  4. Separation of Duties (Self-approval prevention).
  5. Critical Asset Protection Gate (P002).
  6. Cryptographic Audit Chain Genesis-to-Tip Integrity.
  7. Ledger Tamper-Evident Detection.
  8. Monitor API Key HMAC Authentication.
  9. Revoked API Key Invalidation.

### 3.9. API Key Management
* Secure generation and hashing of high-entropy API keys for Wazuh monitors, syslog forwarders, and SIEM collectors.
* Instant revocation and prefix-only display to protect secret credentials.

---

## 4. Technology Stack & Tools Used

| Layer | Technologies & Libraries | Purpose |
|---|---|---|
| **Frontend Framework** | **React 19**, **TypeScript** | Responsive, type-safe single-page user interface |
| **Styling & Icons** | **Tailwind CSS v4**, **Lucide React**, **Motion** | Cyber-themed dark mode UI, micro-animations, accessible telemetry widgets |
| **Bundler & Dev Server** | **Vite 8** | High-performance bundling, Hot Module Replacement, and asset compilation |
| **Backend API Engine** | **Express.js (Node.js 22)** | RESTful API routing, security middleware, and session management |
| **AI & LLM Services** | **Ollama** (Local Models: Llama 3, Mistral) + **Google GenAI SDK (`@google/genai`)** | Zero-cost local threat intelligence & resilient cloud standby triage |
| **Cryptography** | **Node.js Native `node:crypto`** | PBKDF2 (10,000 iterations), SHA-256 Merkle-style audit chaining, CSPRNG tokens |
| **Deployment & Hosting** | **Vercel** (Serverless Function Routing via `/api`), **Node.js standalone** | Production cloud hosting with zero peer-dependency conflicts |

---

## 5. End-to-End Operational Workflow Example

```
[ Step 1: Ingestion ]
    Wazuh Agent detects 10 failed RDP attempts on WIN-DC-01
    -> Sends Syslog JSON to /api/wazuh/ingest with Bearer API Key

[ Step 2: Evaluation ]
    Backend Call Tracker logs the event; Ollama AI analyzes payload
    -> Identifies MITRE T1110.001 (Password Guessing)
    -> Suggests Action: "ISOLATE_HOST" (WIN-DC-01) at Tier L4

[ Step 3: Safety Gate Interception ]
    Policy Engine intercepts:
    -> P002 applies: WIN-DC-01 is designated CRITICAL_ASSET
    -> P004 applies: L4 action requires human approval
    -> Autonomous execution is BLOCKED; Request queued in Approval Inbox

[ Step 4: Human Governance ]
    Lead Approver reviews incident context, parameter hashes, and AI notes
    -> Signs off with justification: "Authorized maintenance window containment"
    -> State transitions to APPROVED

[ Step 5: Immutable Audit Recording ]
    Audit Engine appends Block #42 containing action details and approver signature
    -> Hash chain recalculates and updates cryptographic tip
```

---

## 6. Future Upgrades & Roadmap to Complete the Project

To scale this platform into a commercially deployable or production-ready enterprise SOC defense system, the following roadmap phases are recommended:

### Phase 1: Persistence & Distributed Storage
- [ ] **Database Integration**: Replace the current high-performance in-memory state stores with PostgreSQL / Cloud SQL using Drizzle ORM for persistent alert history, historical audit query archiving, and user management.
- [ ] **Redis / Valkey Cache**: Implement distributed caching for session tokens and sliding-window rate limit counters across multiple server instances.

### Phase 2: Live Bi-Directional Streaming & WebSockets
- [ ] **Socket.IO / WebSockets Gateway**: Implement live push streaming so that newly ingested Wazuh alerts, backend API errors, and pending approval notifications appear on all connected analyst screens with sub-second latency without polling.
- [ ] **Audio-Visual Alert Staging**: Configurable audio alarms and desktop push notifications for Critical (Severity Level 12+) detections.

### Phase 3: Active Response Orchestration (SOAR)
- [ ] **Real Network Agents & Webhook Connectors**:
  * Real Cisco / Fortinet / Palo Alto firewall rule updates via REST APIs.
  * Cloud security groups automation (AWS Security Groups, Cloudflare IP Access Rules, GCP Firewall Policies).
  * Windows Active Directory LDAP connector to disable compromised user accounts directly.
- [ ] **Ansible / SSH Playbook Execution**: Automated execution of verified containment playbooks against designated staging targets.

### Phase 4: Enhanced AI & Threat Intelligence Enrichments
- [ ] **STIX / TAXII & MISP Ingestion**: Feed real-time commercial and open-source threat intelligence feeds directly into the AI prompt context.
- [ ] **RAG (Retrieval-Augmented Generation) Knowledge Base**: Embed internal company network topology, incident runbooks, and past post-mortems into a local vector database (e.g., ChromaDB / pgvector) to provide context-aware AI recommendations.
- [ ] **Multi-Agent Red-Team / Blue-Team Simulations**: Run autonomous simulated adversary agents against the SOC to continuously evaluate defensive rule efficacy.

### Phase 5: Enterprise Compliance & Exporting
- [ ] **One-Click Regulatory Compliance Reports**: Automated generation of audit reports formatted for SOC2 Type II, ISO 27001, and HIPAA compliance directly from the cryptographic hash chain.
- [ ] **SIEM Bi-directional Sync**: Ready-made integrations to mirror events to Splunk, Microsoft Sentinel, and Elastic SIEM.

---

## 7. Conclusion

AI-SOC demonstrates how artificial intelligence and deterministic security guardrails can work in synergy. By pairing local, privacy-preserving Ollama intelligence with an unyielding L0–L7 policy gate and cryptographic audit trails, it delivers rapid response capabilities without sacrificing human oversight or system integrity.
