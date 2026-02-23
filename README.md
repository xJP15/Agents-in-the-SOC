# Agents in the SOC

**Structured SOC Triage Execution Engine (Sentinel-first)**

## What This Is

A retrieval-augmented triage system that ingests Microsoft Sentinel alerts, retrieves relevant runbook context from a vector database, and produces structured triage reports via LLM. Built on Langflow with ChromaDB for runbook embeddings and GPT-4o for analysis.

The system outputs deterministic, schema-valid JSON triage reports designed for analyst review and downstream automation.

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
- ChromaDB vector store with 6 security runbooks
- MITRE ATT&CK mapping per alert
- Confidence scoring
- Basic containment action suggestions

**In Progress:**

- Deterministic alert-to-retrieval query generation
- Strict JSON schema enforcement for all outputs
- Output normalization
- Sentinel-specific KQL query generation (read-only)

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

| Component | Type | Configuration | Purpose |
|-----------|------|---------------|---------|
| **Directory** | File Loader | Path: `kb/`, Depth: 0 | Load runbook markdown files |
| **Split Text** | Text Splitter | Chunk: 500, Overlap: 50 | Split runbooks into retrievable chunks |
| **Chroma DB** | Vector Store | Collection: `langflow` | Store and search runbook embeddings |
| **OpenAI** | LLM | Model: `gpt-4o`, Temp: 0.10 | Generate triage analysis |

### Data Flow

1. **Poll**: `incident_poller.py` queries Sentinel for `SecurityIncident` records
2. **Normalize**: Raw incidents converted to structured alert JSON
3. **Route**: Alert type inferred from title and MITRE techniques
4. **Retrieve**: Langflow queries ChromaDB for relevant runbook chunks
5. **Generate**: LLM produces triage report with recommended actions
6. **Output**: Report saved to `outputs/` directory

---

## Short-Term Roadmap

Target: 4-6 weeks

- Verifier LLM gate to detect hallucinations and unsupported claims
- Evaluation harness with curated alert test set
- Citation enforcement linking recommendations to source runbooks
- Triage quality metrics and scoring
- Structured logging for all pipeline outputs

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

| Runbook | Alert Types Covered |
|---------|-------------------|
| `impossible_travel.md` | Atypical sign-in, geo anomaly, risky sign-in |
| `mfa_fatigue.md` | Push bombing, MFA spam, authentication fatigue |
| `oauth_consent_abuse.md` | Malicious app consent, illicit consent grant |
| `mailbox_rule_abuse.md` | Inbox forwarding, mail rules, BEC indicators |
| `phishing_click.md` | Safe Links clicks, credential harvesting |
| `password_spray.md` | Brute force, credential stuffing |

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
git clone https://github.com/yourusername/Agents-in-the-SOC.git
cd Agents-in-the-SOC

python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure no secrets are committed
4. Submit a pull request

---

## License

MIT License
