# Agents in the SOC

**Structured SOC Execution Framework**

## What This Is

A Sentinel-first triage execution framework that uses curated runbooks and reference packs to generate structured, deterministic triage outputs. The LLM acts as an orchestrator that parameterizes approved detection logic rather than generating novel security content.

Built on Langflow with ChromaDB for retrieval and GPT-4o for structured output generation. All outputs are JSON-validated and designed for human review before action.

## Why This Matters

LLMs in security workflows introduce hallucination risk. An ungrounded model can fabricate MITRE techniques, invent KQL syntax, or recommend actions without evidence. This framework mitigates that risk by:

- Treating the LLM as orchestrator, not source of truth
- Retrieving detection logic from curated, version-controlled packs
- Enforcing structured outputs that can be validated
- Requiring human review before any action

The goal is deterministic, auditable triage that analysts can trust.

## Current Scope (v1)

**Implemented:**
- Sentinel alert ingestion via Log Analytics API
- Runbook RAG retrieval (ChromaDB)
- Baseline structured JSON triage output
- MITRE ATT&CK mapping (baseline)
- Confidence scoring
- Query builder (gpt-4o-mini, 3-6 word deterministic queries)

**In Progress:**
- Strict JSON schema enforcement
- Separation of runbook and reference knowledge
- Output normalization

**v1 Hardening Focus:** password_spray, mailbox_rule_abuse, oauth_consent_abuse

## Production-Grade Direction

The architecture is evolving toward curated reference packs:

**Reference Pack Model:**
- MITRE reference packs: Approved tactic/technique mappings per alert type
- KQL reference packs: Parameterized query templates for evidence gathering
- Detection-as-code: Version-controlled, peer-reviewed detection logic

**LLM Role:**
- Selects appropriate reference pack based on alert classification
- Parameterizes KQL templates with entity values (UPN, IP, timestamp)
- Structures output according to enforced schema
- Does not generate novel MITRE mappings or KQL syntax

This approach treats detection logic as code: authored by humans, retrieved by LLM, executed deterministically.

## Short-Term Roadmap


- Implement KQL reference pack structure
- Implement MITRE reference pack structure
- Add verifier LLM gate (hallucination/citation checks)
- Add evaluation harness with curated alert scoring
- Implement read-only KQL enrichment agent

## Long-Term Vision

- Multi-SIEM support (Sentinel, Cortex XSIAM)
- Detection engineering assistant for rule tuning
- False positive feedback loop
- Purple team validation pipeline
- Guardrail framework for SOC AI systems

## Safety and Guardrails

| Principle | Implementation |
|-----------|----------------|
| Human review required | All outputs require analyst approval before action |
| No automated remediation | System recommends, never executes containment |
| Read-only evidence queries | KQL limited to retrieval, no modifications |
| Citation enforcement | Recommendations link to source runbooks |
| Auditable outputs | All triage reports logged with provenance |
| Deterministic retrieval | Queries derived from alert fields, not LLM creativity |

## Non-Goals

This project does not aim to:

- Execute autonomous response actions
- Generate exploit code or attack payloads
- Replace human security analysts
- Support free-form LLM query generation
- Operate as an unguarded automation platform

## Architecture

**Runtime Path:**
```
Alerts JSON
    |
    v
Query Builder (LLM, deterministic)
    |
    v
Runbook Retrieval (ChromaDB)
    |
    v
Reference Pack Retrieval (MITRE + KQL) [planned]
    |
    v
Structured Triage Generator
    |
    v
Verifier Gate [planned]
    |
    v
JSON Output
```

**Current Components:**

| Component | Status | Purpose |
|-----------|--------|---------|
| Sentinel Poller | Implemented | Ingest alerts via Log Analytics API |
| Query Builder | Implemented | Generate deterministic search queries |
| Runbook Retrieval | Implemented | Fetch relevant runbook context |
| Triage Generator | Implemented | Produce structured JSON output |
| Reference Packs | Planned | Curated MITRE/KQL knowledge |
| Verifier Gate | Planned | Validate citations and detect hallucination |

## Quick Start

```bash
git clone https://github.com/xJP15/Agents-in-the-SOC.git
cd Agents-in-the-SOC

python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
cp .env.template .env
```

**Required:**
- Python 3.10+
- Microsoft Sentinel workspace
- Entra ID service principal (Log Analytics Reader)
- OpenAI API key

**Run:**
```bash
langflow run
python incident_poller.py --triage
```

## Contributing

This project is evolving. Architecture decisions, reference pack design, and evaluation methods are open for discussion. Contributions and peer review welcome.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License
