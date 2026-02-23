# Agents in the SOC

**Structured SOC Triage Execution Engine (Sentinel-first)**

## What This Is

A retrieval-augmented triage system that ingests Microsoft Sentinel alerts, retrieves relevant runbook context from a vector database, and produces structured triage reports via LLM. Built on Langflow with ChromaDB for runbook embeddings and GPT-4o for analysis.

The system outputs JSON triage reports designed for analyst review and downstream automation. Strict schema enforcement is in progress.

## Why This Matters

Security Operations Centers face alert fatigue and inconsistent triage quality. This system addresses both by:

- Reducing mean-time-to-triage through automated initial assessment
- Providing consistent runbook-guided analysis across all alert types
- Producing auditable, structured outputs that integrate with existing workflows
- Augmenting analysts with contextual guidance rather than replacing human judgment

---

## Current Scope (v1)

**Implemented:**

- Sentinel alert ingestion via Log Analytics API (service principal auth)
- Langflow RAG pipeline with runbook retrieval
- ChromaDB vector store with 6 runbooks (v1 validated against: password_spray, mailbox_rule_abuse, oauth_consent_abuse)
- Deterministic query builder (gpt-4o-mini generates 3-6 word search queries)
- MITRE ATT&CK mapping per alert
- Confidence scoring
- Basic containment action suggestions

**In Progress:**

- Strict JSON schema enforcement for all outputs
- Output normalization

**Planned:**

- Verifier LLM gate (hallucination/citation checks)
- Citation grounding (link to source runbooks)
- KQL enrichment agent (read-only queries)
- Evaluation harness (sample alerts + scoring)

**Triage Output Schema:**

```json
{
  "summary": "string",
  "severity_assessment": "string",
  "mitre_mapping": {"tactics": [], "techniques": []},
  "entities": {"users": [], "ips": [], "hosts": []},
  "investigation_steps": [],
  "kql_queries": [],
  "containment_actions": [],
  "false_positive_checks": [],
  "confidence": 0.0,
  "citations": []
}
```

---

## Architecture

### System Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Microsoft       │     │ Incident Poller  │     │ Langflow        │
│ Sentinel        │────▶│ (Python)         │────▶│ RAG Pipeline    │
│ (Log Analytics) │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                         │
                       ┌──────────────────┐              │
                       │ ChromaDB         │◀─────────────┘
                       │ (Runbook KB)     │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Triage Report    │
                       │ (outputs/)       │
                       └──────────────────┘
```

### Langflow RAG Pipeline

![Langflow Architecture](docs/langflow_architecture.png)

**KB Ingestion Path** (runs once):
```
Directory (kb/) → Split Text → Embedding Model → Chroma DB
```

**Runtime Path** (per alert):
```
Alerts JSON ──┬────────────────────────────────────→ Triage Prompt {alert}
              │                                              │
              ▼                                              │
      Query Builder Prompt                                   │
      ("3-6 word search query")                              │
              │                                              │
              ▼                                              │
      OpenAI (gpt-4o-mini)                                   │
              │                                              │
              ▼                                              │
      Chroma DB (search) → Results → Type Convert → Triage Prompt {context}
                                                             │
                                                             ▼
                                                     OpenAI (gpt-4o)
                                                             │
                                                             ▼
                                                       Triage Output
```

### Components

| Component | Type | Configuration | Purpose |
|-----------|------|---------------|---------|
| **Directory** | File Loader | Path: `kb/`, Depth: 0 | Load runbook markdown files |
| **Split Text** | Text Splitter | Chunk: 500, Overlap: 50 | Split runbooks into chunks |
| **Embedding Model** | OpenAI Embeddings | `text-embedding-3-small` | Generate vector embeddings |
| **Chroma DB** | Vector Store | Collection: `langflow` | Store and search runbooks |
| **Query Builder** | Prompt Template | "3-6 words maximum" | Generate deterministic search query |
| **OpenAI (QB)** | LLM | `gpt-4o-mini`, Temp: 0.10 | Fast query generation |
| **Type Convert** | Data Converter | Output: Message | Convert search results |
| **Triage Prompt** | Prompt Template | `{context}`, `{alert}` | Build triage prompt |
| **OpenAI (Triage)** | LLM | `gpt-4o`, Temp: 0.10 | Generate triage analysis |

### Data Flow

1. **Poll**: `incident_poller.py` queries Sentinel for `SecurityIncident` records
2. **Normalize**: Raw incidents converted to structured alert JSON
3. **Query Build**: Alert passed to Query Builder LLM to generate 3-6 word search query
4. **Retrieve**: Deterministic query searches ChromaDB for relevant runbook chunks
5. **Generate**: Triage LLM produces structured report with runbook context
6. **Output**: Report saved to `outputs/` directory

---

## Short-Term Roadmap


- Strict JSON schema enforcement + output validator
- Verifier LLM gate (hallucination detection)
- Citation enforcement (link recommendations to source runbooks)
- KQL enrichment agent (read-only queries) + evidence bundle
- Evaluation harness (sample alerts + scoring)

---

## Long-Term Vision

- Multi-agent architecture: Triage, Enrichment, Detection Engineer, Response Advisor, Case Manager
- Multi-SIEM support (Cortex XSIAM, Splunk, QRadar)
- Detection engineering assistant for rule tuning and coverage analysis
- False positive feedback loop
- Purple team validation framework
- Guardrail framework for SOC AI systems

---

## Safety and Guardrails

| Principle | Implementation |
|-----------|----------------|
| Human-in-the-loop | All outputs require analyst review before action |
| Read-only queries | KQL execution limited to evidence retrieval, no modifications |
| No autonomous response | System recommends, never executes containment actions |
| Deterministic retrieval | Query generation derived from alert fields, not LLM creativity |
| Auditable outputs | All triage reports logged with full provenance |
| No attack content | System does not generate exploit code or attack payloads |
| Credential protection | `.env` gitignored, secrets never logged, safe `__repr__` methods |

---

## Non-Goals

This project explicitly does not aim to:

- Execute autonomous response actions (block users, isolate hosts, revoke sessions)
- Generate attack simulations or adversary emulation content
- Replace human security analysts
- Provide real-time inline blocking or prevention
- Operate as a multi-tenant SaaS platform
- Support unstructured or free-form LLM outputs

---

## Project Structure

```
Agents-in-the-SOC/
├── config.py               # Configuration loader
├── sentinel_client.py      # Sentinel/Log Analytics API client
├── incident_poller.py      # Polling with deduplication
├── langflow_client.py      # Langflow API client for triage
├── dashboard.py            # Web dashboard for triage reports
│
├── kb/                     # Runbook knowledge base
│   ├── impossible_travel.md
│   ├── mfa_fatigue.md
│   ├── oauth_consent_abuse.md
│   ├── mailbox_rule_abuse.md
│   ├── phishing_click.md
│   └── password_spray.md
│
├── chroma/                 # ChromaDB persistence (gitignored)
├── outputs/                # Generated triage reports
└── state/                  # Poller cursor state
```

### Runbooks

**v1 Hardening Focus:**
- `password_spray.md` - Brute force, credential stuffing
- `mailbox_rule_abuse.md` - Inbox forwarding, mail rules, BEC indicators
- `oauth_consent_abuse.md` - Malicious app consent, illicit consent grant

**Also Available:**
- `impossible_travel.md` - Atypical sign-in, geo anomaly, risky sign-in
- `mfa_fatigue.md` - Push bombing, MFA spam, authentication fatigue
- `phishing_click.md` - Safe Links clicks, credential harvesting

---

## Quick Start

### Prerequisites

- Python 3.10+
- Microsoft Sentinel workspace with Log Analytics
- Entra ID service principal with Log Analytics Reader role
- Langflow instance
- OpenAI API key

### Setup

```bash
git clone https://github.com/xJP15/Agents-in-the-SOC.git
cd Agents-in-the-SOC

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
cp .env.template .env
# Edit .env with your credentials
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AZURE_TENANT_ID` | Entra ID tenant |
| `AZURE_CLIENT_ID` | Service principal app ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `LOG_ANALYTICS_WORKSPACE_ID` | Sentinel workspace ID |
| `LANGFLOW_FLOW_ID` | Langflow flow identifier |

### Run

```bash
# Start Langflow
langflow run

# Poll and triage
python incident_poller.py --triage

# Continuous mode
python incident_poller.py --triage --continuous

# Dashboard
python dashboard.py  # http://localhost:8080
```

---

## Building in Public

This project is evolving. The architecture, outputs, and tooling are actively being refined based on real-world SOC workflows. Contributions, feedback, and discussions are welcome.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure no secrets are committed
4. Submit a pull request

---

## License

MIT License
