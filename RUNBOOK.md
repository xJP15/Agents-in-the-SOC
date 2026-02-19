# SOC RAG + Sentinel Integration Runbook (Langflow-based)

**Version:** 0.3
**Owner:** Juan Urena
**Last updated:** 2026-02-18

---

## 0) What this is

This runbook documents the end-to-end build of a production-minded SOC RAG triage system using Langflow, OpenAI models, a local Chroma vector store, and Microsoft Sentinel (Log Analytics API) as a real alert source.

It is written to be:
- **Repeatable** (new machine, same results)
- **Explainable** (architect/interviewer-ready)
- **Extensible** (future agent workflows / SOAR integrations)
- **Safe** (least privilege + secrets hygiene)

**Primary objective:** Automated triage that injects runbook context, maps to MITRE, and recommends actions.

**Near-term objective:** Convert outputs into machine-actionable JSON for automation and SOC workflows.

---

## 1) Goals and non-goals

### 1.1 Goals
- Auto-triage alerts/incidents
- Inject runbook context (RAG)
- Produce consistent triage output (human-readable now; JSON later)
- Map to MITRE (tactics/techniques)
- Recommend containment actions and follow-ups
- Connect to a real SIEM source (Sentinel) for realistic inputs
- Build a foundation for multi-agent SOC workflows (routing, enrichment, response suggestions)

### 1.2 Non-goals (for Phase 1)
- No automatic remediation actions (disable user / block IP / isolate endpoint)
- No write-back to Sentinel (close incident, add comments) yet
- No public exposure of Langflow endpoints
- No multi-agent orchestration until structured outputs + evaluation are in place

---

## 2) High-level architecture

### 2.1 Components
| Component | Purpose |
|-----------|---------|
| Langflow (local) | Orchestration / flow execution and API |
| OpenAI GPT-4o | Generation (triage report) |
| OpenAI text-embedding-3-small | Embeddings |
| Chroma DB (local persistent) | Vector store |
| Runbooks (Markdown) in `/kb` | Knowledge base |
| Microsoft Sentinel | Source of incidents (SecurityIncident table) |
| Poller script (Python) | Pulls incidents and forwards to Langflow API |

### 2.2 Data flow overview

**A) Offline Index Build (when KB changes)**
```
/kb Markdown files
    -> Split Text (chunking)
    -> Embeddings (text-embedding-3-small)
    -> Chroma Ingest (persisted vectors)
```

**B) Runtime Triage (per incident/alert)**
```
Sentinel SecurityIncident
    -> Poller (query + normalization)
    -> Langflow API /api/v1/run/{flow_id}
    -> Chroma Search (retrieve top-k chunks)
    -> Prompt Template (alert + context)
    -> GPT-4o (triage output)
    -> Response returned to poller (and stored/logged)
```

---

## 3) Current state (what is working)

### 3.1 Langflow RAG Pipeline - WORKING
- Flow: "SOC Triage Agent v1" fully functional
- Directory → Split Text (chunk 500, overlap 50) → Chroma DB (collection: "langflow")
- Embedding Model: OpenAI text-embedding-3-small
- Alerts JSON → Chroma Search → Type Convert → Prompt Template → GPT-4o (temp 0.10)
- System prompt: Tier 2 SOC analyst persona
- Tested with JSON alerts, produces quality triage output

### 3.2 Sentinel Integration - WORKING
- OAuth client credentials flow working
- Token caching with auto-refresh implemented
- Log Analytics API queries return SecurityIncident rows
- Incident poller with deduplication and state management working
- Alert type inference maps incidents to runbook categories

### 3.3 Poller → Langflow Integration - WORKING
- `langflow_client.py` handles API communication
- Poller sends normalized incidents to Langflow via REST API
- Triage outputs saved to `outputs/` as markdown files
- Structured JSON triage reports with confidence scores

### 3.4 Resolved Issues
- Fixed: Azure token endpoint Content-Type header (was sending JSON, needed form-urlencoded)
- Fixed: Langflow API run errors due to unconfigured nodes in graph
- Fixed: Langflow API response parsing (needed TextOutput component in flow)

### 3.5 Phase 1 Status: COMPLETE
End-to-end pipeline working: Sentinel → Poller → Langflow RAG → GPT-4o → Triage Report

---

## 4) Prerequisites

### 4.1 Local environment
- Windows machine (example paths below)
- Python 3.10+ with venv
- Langflow installed and runnable locally (v1.7.2 currently)
- Chroma local persistence directory configured
- OpenAI API key available for embeddings + generation

### 4.2 Azure environment (Sentinel)
- Microsoft Sentinel connected to a Log Analytics Workspace
- Incidents present (or test incidents created) in SecurityIncident

### 4.3 Dependencies
Install via `pip install -r requirements.txt`:
```
requests>=2.31.0        # HTTP client for API calls
python-dotenv>=1.0.0    # Environment variable management
chromadb>=0.4.0         # Vector database for RAG
```

Langflow is installed separately in the venv.

---

## 5) Directory layout

```
C:\Users\Jpure\soc-langflow-lab\
  kb\                   # runbooks (.md)
  chroma\               # Chroma persistence (vector DB)
  outputs\              # triage outputs (markdown reports)
  state\                # poller cursor (dedup state)
  venv\                 # Python virtual environment
  .env                  # secrets (NEVER commit)
  .env.template         # placeholders only (safe to commit)
  .gitignore            # ignore .env, chroma/, outputs/, state/, venv/
  config.py             # Configuration loader with validation
  sentinel_client.py    # Sentinel API client
  incident_poller.py    # Poller with deduplication and normalization
  langflow_client.py    # Langflow API client for triage
  requirements.txt      # Python dependencies
```

---

## 6) Project files reference

### 6.1 config.py
Configuration management using dataclasses. Loads settings from `.env` with validation.

**Key features:**
- `SentinelConfig` dataclass with required field validation
- Safe `__repr__` that redacts secrets
- Project path constants (`STATE_DIR`, `KB_DIR`, `OUTPUTS_DIR`, `CHROMA_DIR`)
- Auto-creates directories on import

**Usage:**
```python
from config import load_config, STATE_DIR
config = load_config()
```

### 6.2 sentinel_client.py
Microsoft Sentinel / Log Analytics API client.

**Key features:**
- OAuth2 client credentials authentication
- Token caching with automatic refresh (5-minute buffer before expiry)
- Retry logic with exponential backoff
- Rate limit handling (429 responses)
- KQL query execution

**Key methods:**
- `test_connection()` - Verify connectivity
- `get_security_incidents(since, limit)` - Query SecurityIncident table
- `get_security_alerts(since, limit)` - Query SecurityAlert table
- `execute_query(query)` - Run arbitrary KQL

**Usage:**
```python
from config import load_config
from sentinel_client import SentinelClient

config = load_config()
client = SentinelClient(config)
client.test_connection()
incidents = client.get_security_incidents(limit=10)
```

### 6.3 incident_poller.py
Polls Sentinel for new incidents with deduplication and cursor management.

**Key features:**
- Persistent state tracking (seen IDs, last poll time, cursor)
- Duplicate detection (keeps last 1000 incident IDs)
- Incident normalization to structured schema
- Alert type inference (maps to runbook categories)
- Callback system for processing new incidents

**Key classes:**
- `PollerState` - Persistent state dataclass
- `StateManager` - Saves/loads state to `state/poller_state.json`
- `NormalizedIncident` - Structured incident with `to_alert_schema()` method
- `IncidentPoller` - Main poller with `poll_once()` and `run()` methods

---

## 7) Knowledge base (runbooks)

### 7.1 Current runbooks
```
kb/
  password_spray.md
  impossible_travel.md
  mfa_fatigue.md
  oauth_consent_abuse.md
  mailbox_rule_abuse.md
  phishing_click.md
```

### 7.2 Runbook format guidance
Each runbook should include:
- Definition (what this alert is)
- Key signals (what to look for)
- Data sources (which logs)
- Triage steps (what to check in order)
- MITRE mapping (tactics/techniques)
- Response actions (containment + eradication + recovery)
- Suggested retrieval keywords (optional but useful)
- Example KQL/XQL queries (later phase)

### 7.3 Alert type inference
The poller automatically maps incidents to runbook categories based on title/description keywords:

| Alert Type | Keywords |
|------------|----------|
| `impossible_travel` | impossible travel, atypical, unfamiliar location, sign-in from |
| `mfa_fatigue` | mfa, multi-factor, push, fatigue, authentication attempt |
| `oauth_consent_abuse` | oauth, consent, application consent, app permission |
| `mailbox_rule_abuse` | inbox rule, forwarding, mail rule, mailbox |
| `phishing_click` | phish, malicious link, click, url, safe links |
| `password_spray` | password spray, brute force, failed login, credential |
| `unknown` | (default if no match) |

---

## 8) Environment variables

### 8.1 Required variables
Copy `.env.template` to `.env` and fill in values:

```bash
# Microsoft Entra ID (Azure AD) Service Principal
AZURE_TENANT_ID=your-tenant-id-here
AZURE_CLIENT_ID=your-client-id-here
AZURE_CLIENT_SECRET=your-client-secret-here

# Log Analytics Workspace
LOG_ANALYTICS_WORKSPACE_ID=your-workspace-id-here
```

### 8.2 Optional variables
```bash
# Polling interval in seconds (default: 60)
POLL_INTERVAL_SECONDS=60

# How far back to look on first run (default: 24 hours)
INITIAL_LOOKBACK_HOURS=24

# Langflow API Key (from Langflow settings)
LANGFLOW_API_KEY=your-langflow-api-key-here
```

---

## 9) Normalized alert schema

The poller normalizes Sentinel incidents into this structured format for Langflow:

```json
{
  "alert_type": "impossible_travel",
  "incident_id": "12345",
  "title": "Sign-in from unfamiliar location",
  "severity": "medium",
  "status": "New",
  "time_generated": "2026-02-18T10:30:00Z",
  "source_provider": "Azure Sentinel",
  "mitre": {
    "tactics": ["InitialAccess"],
    "techniques": ["T1078"]
  },
  "entities": {
    "users": ["user@contoso.com"],
    "ips": ["203.0.113.50"],
    "hosts": [],
    "apps": ["Office 365"],
    "urls": [],
    "files": []
  },
  "description": "A sign-in was detected from a location...",
  "incident_url": "https://portal.azure.com/...",
  "related_alert_ids": ["alert-guid-1", "alert-guid-2"]
}
```

**Note:** The `alert_type` is inferred automatically to enable runbook matching. Empty entity arrays are excluded from actual output.

---

## 10) Langflow flows: design intent

### 10.1 Current working flow (combined)
For learning, initially acceptable. For production, split later.

Nodes you currently have:
- Directory -> Split Text -> Chroma Ingest (indexing)
- Alert Text Input -> Chroma Search -> Prompt Template -> OpenAI (triage)
- Type Convert (temporary for context shaping)

### 10.2 Target design (best practice)
Split into two flows:

**Flow A: Index Builder**
- Run only when `/kb` changes

**Flow B: Runtime Triage**
- Run per incident/alert

This prevents accidental re-indexing and mirrors production pipelines.

---

## 11) Retrieval concepts (educational)

### 11.1 What Top-K means
Top-K = number of nearest chunks returned by vector similarity search.
- K=1: highest precision, least context
- K=2-3: better coverage, risk of irrelevant context if KB grows

**Rule of thumb:** Start with K=2, validate across categories, then tune.

### 11.2 Why context shaping matters
Raw vector search results are often objects/lists. LLMs perform better when you pass:
- Only the chunk text (page_content)
- Small metadata (source filename)
- Clean separators between chunks

**Avoid:**
- Stringified objects/dicts
- Giant prompt bloat
- Irrelevant chunks

---

## 12) Microsoft Sentinel integration (Phase 1: read-only)

### 12.1 Azure identities used
Service Principal (App Registration) with least privilege.

**Required identifiers:**
- Tenant ID
- Client ID
- Client Secret (rotate if exposed)
- Workspace ID (Log Analytics Workspace GUID)

### 12.2 Permissions
Assign Azure RBAC on the Log Analytics Workspace:
- **Role:** Log Analytics Reader

**Reason:** Enables read-only query access via Log Analytics API

### 12.3 Token acquisition (OAuth client credentials)
```
Token endpoint: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Scope: https://api.loganalytics.io/.default
```

### 12.4 Query endpoint (Log Analytics API)
```
POST: https://api.loganalytics.io/v1/workspaces/{workspaceId}/query
Body: { "query": "<KQL>" }
```

### 12.5 Validation test (minimum)
```kql
SecurityIncident | take 5
```
Expected: 200 OK, PrimaryResult, rows >= 0

---

## 13) Langflow API integration

### 13.1 Why this matters
This turns your Langflow triage flow into a local SOC microservice:
- Poller can POST incidents
- Flow runs headlessly
- Output can be captured and stored

### 13.2 Flow ID
Your flow ID (example):
```
c2d71899-eb9d-421b-b390-fafa84600a76
```

### 13.3 Endpoint format (Langflow REST)
```
POST: http://127.0.0.1:7860/api/v1/run/{flow_id_or_name}?stream=false
```

### 13.4 Authentication gotcha (Langflow v1.5+)
Observed error:
```
LANGFLOW_AUTO_LOGIN requires a valid API key
```

**Resolution options:**

**A) Lab-only:** Disable auto-login check
```powershell
$env:LANGFLOW_SKIP_AUTH_AUTO_LOGIN = "true"
.\venv\Scripts\langflow.exe run
```

**B) Production-minded:** Use Langflow API key auth
- Create API key in Langflow UI
- Store in `.env` as `LANGFLOW_API_KEY`
- Send via `x-api-key` header

### 13.5 Critical gotcha: unconfigured nodes can break API run
Langflow may validate/build the entire graph on API execution. Even an unconnected node can cause failure if required fields are empty.

**Example failure:** `"URL cannot be empty"`
**Root cause:** API Request node present with empty URL (even though not connected)
**Fix:** Remove the node OR set a dummy URL

---

## 14) How to run the components

### 14.1 Activate virtual environment
```powershell
# PowerShell
.\venv\Scripts\Activate.ps1

# CMD
venv\Scripts\activate
```

### 14.2 Test Sentinel connection
```powershell
python sentinel_client.py
```
Expected output: "Connection test successful" and list of recent incidents

### 14.3 Run poller (poll only)
```powershell
python incident_poller.py
```
This will:
- Load config from `.env`
- Poll Sentinel for incidents (last 24 hours on first run)
- Normalize and display new incidents
- Save state to `state/poller_state.json`

### 14.4 Run poller with triage
```powershell
python incident_poller.py --triage
```
This will:
- Poll Sentinel for new incidents
- Send each to Langflow for RAG-based triage
- Save triage reports to `outputs/`

### 14.5 Run continuous polling with triage
```powershell
python incident_poller.py --triage --continuous
```

### 14.6 Start Langflow
```powershell
# With venv activated
langflow run

# Or directly without activation
.\venv\Scripts\langflow.exe run

# With auth disabled (lab only)
$env:LANGFLOW_SKIP_AUTH_AUTO_LOGIN = "true"
.\venv\Scripts\langflow.exe run
```
Default URL: http://127.0.0.1:7860

### 14.5 Run continuous polling (when ready)
Uncomment in `incident_poller.py`:
```python
poller.run(max_iterations=5)  # or remove limit for infinite
```

---

## 15) Step-by-step setup (repeatable)

### A) Local RAG setup
1. Create folders: `kb\`, `chroma\`, `outputs\`, `state\`
2. Add Markdown runbooks to `kb\`
3. In Langflow:
   - Configure Directory node path to `kb\`
   - Configure Chroma persist directory to `chroma\`
   - Configure Embedding Model: text-embedding-3-small (OpenAI key)
   - Ingest data (index build)
4. Runtime:
   - Alert input -> Chroma Search -> Prompt -> GPT-4o
   - Validate correct runbook retrieval and triage output

### B) Sentinel read-only setup
1. Create App Registration (service principal)
2. Create client secret (store securely; rotate if exposed)
3. Assign RBAC role on workspace: **Log Analytics Reader**
4. Copy `.env.template` to `.env` and fill in values
5. Test: `python sentinel_client.py`

### C) Langflow API setup
1. Confirm Langflow server is reachable:
   - http://127.0.0.1:7860
   - http://127.0.0.1:7860/docs
2. Ensure flow runs via API endpoint
3. If blocked by auth:
   - Use API key auth OR set `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true`
4. Remove any unconfigured nodes (e.g., API Request with empty URL)

### D) Connect poller -> Langflow
1. Poller queries SecurityIncident
2. Poller normalizes incident using `to_alert_schema()`
3. Poller POSTs JSON into Langflow `/api/v1/run/{flow_id}`
4. Poller stores triage output in `outputs\` and updates cursor in `state\`

---

## 16) Best practices

### 16.1 Security
- Treat any pasted secret/API key as compromised and rotate immediately
- Use `.env` (gitignored) or OS env vars for secrets
- Keep Langflow bound to 127.0.0.1 during development
- Principle of least privilege: Log Analytics Reader only (read-only)
- Never include raw incident data in logs (use normalized schema)

### 16.2 Reliability
- Split index flow from runtime flow
- Add logging:
  - incident id
  - time pulled
  - flow execution status
  - model response id (if available)
- Keep cursor state to prevent duplicates
- Implement retries with backoff (already in sentinel_client.py)

### 16.3 RAG quality
- Keep runbooks consistent in structure
- Tune chunk size/overlap based on runbook length:
  - 300-600 chunk size often fine for runbooks
  - overlap 30-80 often reasonable
- Keep top-k small (2-3) until KB grows
- Add context formatter (later) to avoid messy object injections

### 16.4 Maintainability
- Version your prompts (add prompt_version in header)
- Track runbook versions (front-matter metadata or filename suffix)
- Keep a regression set of test alerts to validate changes

---

## 17) Common gotchas (documented)

| Issue | Solution |
|-------|----------|
| Langflow API run fails with empty field error | Remove unconfigured nodes or set dummy values |
| Langflow API returns empty outputs | Add TextOutput component connected to OpenAI output |
| 403 on Langflow API (v1.5+) | Set `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=true` or use API key |
| .env not loaded in PowerShell | Load manually or restart terminal after editing |
| KB changes not reflected | Re-run index build; Chroma doesn't auto-watch |
| Duplicate incidents processed | Check `state/poller_state.json` for cursor issues |
| Token expired errors | Token cache handles this; if persists, check clock sync |
| Rate limiting (429) | Built-in retry with backoff in sentinel_client.py |
| Azure "Malformed JSON" error | Token endpoint needs form-urlencoded, not JSON Content-Type |

---

## 18) Roadmap

### Phase 1: Operational integration - COMPLETE
- [x] Poll Sentinel incidents automatically
- [x] Send to Langflow API for RAG-based triage
- [x] Save structured triage output to `outputs/`
- [x] Deduplication and state management
- [x] Alert type inference for runbook matching

### Phase 2 (current): Context shaping + retrieval hardening
- Replace Type Convert with context formatter
- Include source metadata (runbook file name)
- Add context budget (max chars) and stable separators
- Add retrieval debug output (which chunks were used)

### Phase 3: Structured JSON output
- Enforce strict JSON schema from GPT (severity/confidence/entities/mitre/actions/queries)
- Add validator and JSON repair retry loop
- This becomes your automation interface

### Phase 4: SOC agent expansion
- Router/classifier (alert category routing)
- Enrichment agent (generate KQL and optionally run read-only queries)
- Action recommender agent (guardrails + human approval)
- Queue/prioritization engine

### Phase 5: Evaluation and hardening
- Build a test suite of 30-50 incidents
- Measure retrieval precision, correctness, and consistency
- Add prompt + runbook versioning and change controls

---

## 19) Future SOC agent use cases

- Auto-triage for top incident categories (identity/email/endpoint)
- Auto-enrichment via read-only KQL queries (IP reputation, sign-in timeline, mailbox rules)
- Auto-generation of analyst checklists and escalation notes
- Auto-tagging incidents (MITRE, severity) and routing to queues
- SOAR recommendations (not execution) with confidence/guardrails
- Continuous improvement loop: human feedback -> runbook updates -> re-index -> regression tests

---

## 20) Quick reference commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Test Sentinel connection
python sentinel_client.py

# Run single poll
python incident_poller.py

# Start Langflow (lab mode)
$env:LANGFLOW_SKIP_AUTH_AUTO_LOGIN = "true"
langflow run

# Start Langflow (direct)
.\venv\Scripts\langflow.exe run

# Check Langflow API docs
# Open: http://127.0.0.1:7860/docs
```

---

*End of document*
