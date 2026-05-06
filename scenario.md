# ⚔️ Akagami Scenario Log: ClearTax Vulnerability Assessment

**Target:** ClearTax (Bug Bounty Program)
**Scope:** `*.cleartax.com`, `*.clear.in`, `*.cleartax.in`
**Objective:** High-quality, ethically-compliant security audit moving beyond passive recon to identify P1/P2 vulnerabilities (IDOR, Auth bypass, Privilege Escalation).

---

## 🛠️ Phase 1: Engine Hardening & Tool Integration
Before attacking the target, the Akagami engine underwent major structural upgrades to ensure bug-bounty readiness:
- **Deterministic Parsers:** Ripped out fragile LLM-based parsing and replaced them with robust regex/JSON parsers for `whois` and `theHarvester`.
- **Parallel Orchestration:** Refactored `MasterOrchestrator` to use `asyncio.gather()`, converting a sequential loop into a parallel executor. This dropped scan times from ~30 minutes down to <3 minutes (10x speedup).
- **Tool Arsenal Expansion:** Integrated and wired up `subfinder`, `gau`, `katana`, and fixed the `httpx` to `httpx-pd` binary conflict in `config/tools.yaml`.
- **OpSec Enforcement:** Enforced the `X-Comolho-Client: akagami-recon` header across tools and ensured strict scope boundary alignment with ClearTax VDP rules.

## 🕵️ Phase 2: External Reconnaissance
With the engine optimized, passive and active recon phases yielded massive amounts of data:
- **Subdomain Enumeration:** 101+ subdomains discovered across the 3 wildcard domains (vs. 12 from standard crt.sh).
- **Live Hosts & Tech Stack:** 51 live hosts confirmed. Found that ClearTax relies heavily on React SPAs, Python (Django) auth backends, and GraphQL data layers behind CloudFront WAFs.
- **Historical Data:** 17,945 historical URLs recovered from the Wayback Machine via `gau`.
- **Infrastructure Mapping:** Discovered 12 high-value sandbox/dev environments (`accounts-sandbox`, `app-dev`, `irp-sandbox`, `itservicedesk`).
- **JS Bundle Analysis:** Used `katana` to crawl JavaScript. Found internal API route structures (`einvoicingbe/v1/`) and references to internal features like `userImpersonation`.

## 🛡️ Phase 3: SPA / WAF Shielding & Strategic Pivot
- **The Blocker:** The SPA architecture heavily masked the API endpoints, returning HTML shells for direct curl requests. Unauthenticated API fuzzing was immediately blocked (403) by CloudFront WAF.
- **The Pivot:** Unauthenticated testing was determined to be a dead-end for P1/P2 bugs. We shifted to a manual, authenticated-testing approach using an ephemeral browser agent to intercept XHR/Fetch calls directly from the DOM.

## 🔓 Phase 4: Authenticated IDOR Testing (The Exploit Phase)
- **Account Creation:** Created an account using a temporary email (`cadaede@mailto.plus`) on `accounts-sandbox.cleartax.com`, but hit a hard blocker requiring KSA VAT/Business registration.
- **India Bypass:** Pivoted to the main India portal (`accounts.cleartax.in`). Successfully registered, verified the email, bypassed the PAN requirement, and accessed the ITR (Income Tax Return) dashboard.
- **API Interception:** Injected a custom XHR/Fetch interceptor via the browser subagent. Captured the exact, authenticated GraphQL queries the app was making to `POST /graphql` on `cleartax.in`.
- **Entity Identification:** Identified the user's unique `entityId` parameter (e.g., `1E_SZBFbHE-JtdKRLpQqQQ`).
- **The Attack:** Executed IDOR payloads by replaying the `getClientDocs` and `getPersonalInfo` GraphQL queries, substituting our own `entityId` with modified, invalid, and foreign IDs to see if we could steal another user's PAN, Aadhaar, and Tax data.

## 📊 Phase 5: Final Results & Findings

### Verdict: IDOR is Properly Blocked ❌
ClearTax correctly implements entity-level authorization. When attempting to access another user's data by modifying the `entityId`, the server returned a `CUSTOM_UN_AUTHORIZED` response instead of leaking data. The API is secure against direct IDOR attacks.

### Finding 1: GraphQL Schema Disclosure via Error Suggestions (P4 - Informational)
- **Impact:** While GraphQL Introspection was correctly disabled, the API returned overly verbose error messages.
- **Details:** When querying invalid fields (e.g., querying `firstName` on `PermanentInfo`), the server responded with: *"Cannot query field 'firstName' on type 'PermanentInfo'. Did you mean to use an inline fragment on 'PersonalInfo'?"*
- **Result:** This allowed us to systematically map out the hidden GraphQL schema (types and fields) without needing introspection access.

### Finding 2: Exposed Sandbox/Dev Environments (P4 - Informational)
- **Details:** 12 environments (including `app-dev.cleartax.com`) are accessible to the public internet and serve development JS bundles (from a `/development/` CDN path), which can leak internal infrastructure details and staging logic.

---
**Status:** Engagement Completed. Final reports generated in `/workspace/cleartax/output/reports/`. Tool is primed and ready for the next target.

## 🤖 The Akagami Playbook: How We Approach a New Target
When a new target is provided, the Akagami engine follows a strict, multi-stage methodology to ensure comprehensive coverage without violating rules of engagement:

### Step 1: Initialization & Scope Definition
- **Workspace Creation:** A dedicated workspace (`workspace/<company>`) is automatically generated.
- **Scope Loading:** In-scope and out-of-scope domains/IPs are loaded into the central configuration.
- **Rules of Engagement:** The `ToolBus` is initialized with strict OpSec controls, header injection (`X-Comolho-Client`), and explicit permissions (e.g., active scanning allowed/denied).

### Step 2: Passive Reconnaissance (OSINT Agent)
- **Subdomain Enumeration:** `subfinder` and `crt.sh` are executed to map out the target's external footprint.
- **Data Harvesting:** `theHarvester` and `whois` gather emails, employee names, and infrastructure ownership details.
- **Historical Discovery:** `gau` (GetAllUrls) pulls years of historical endpoints, tokens, and parameters from the Wayback Machine.

### Step 3: Active Reconnaissance & Mapping (ActiveRecon Agent)
- **Host Discovery:** `httpx-pd` probes discovered subdomains to identify live web servers, status codes, titles, and tech stacks.
- **Port Scanning:** `nmap` conducts stealthy SYN scans on discovered IP blocks to find open services and banner grab.
- **Directory Fuzzing:** `ffuf` runs targeted wordlists against live web servers to uncover hidden administrative panels, API endpoints, and backup files.
- **JS Crawling:** `katana` extracts deep links, API routes, and hidden features from modern single-page applications (SPAs).

### Step 4: Vulnerability Analysis (VulnAnalysis Agent)
- **Pattern Matching:** `nuclei` scans for known CVEs, misconfigurations, and exposed panels using a curated set of templates (filtered to High/Critical severities).
- **CVE Correlation:** The `CveEnricher` (Groq + ChromaDB) correlates discovered software versions against the NVD database.
- **Critic Review:** The `CriticAgent` (NIM DeepSeek) reviews all raw findings, rejecting false positives and refining data before it enters episodic memory.

### Step 5: Advanced & Authenticated Exploitation (Exploit Planner)
- If unauthenticated external surfaces are heavily shielded (e.g., WAFs, SPAs), Akagami pivots to authenticated testing.
- **Browser Automation:** A browser subagent creates accounts, bypasses basic flows, and intercepts authenticated XHR/Fetch/GraphQL calls.
- **IDOR & Logic Flaws:** Automated or guided manipulation of entity IDs, JWT tokens, and API parameters to test for horizontal/vertical privilege escalation.

### Step 6: Reporting & Synthesis
- Findings are dynamically scored by the `SeverityScorer` based on CVSS and environmental context.
- Executive summaries and Markdown reports are generated via Jinja2 templates, ready for client delivery or VDP (Vulnerability Disclosure Program) submission.
