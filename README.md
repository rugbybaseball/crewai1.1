# FinServe Digital Bank – BCM & Change Management Agent Simulation

A multi-agent system that exercises both **incident-driven business continuity** and **planned ITIL change management** for a fictional digital bank, powered by CrewAI and a local Ollama LLM.

The repo is intentionally a starter: students customize the agents, tools, and tasks; the simulation engine grades the run.

## What's modeled

The system runs in two flow shapes selected by the scenario:

| Flow | When it runs | Tasks | Agents that participate |
|---|---|---|---|
| **Incident response** (with emergency CAB) | One of the 6 incident scenarios | classify → BIA → contain → recover → emergency CAB (tech review → risk review → decision → PIR) → comms | Detection, Impact, SecOps, Recovery, Comms + the 3 CAB roles |
| **Standard change** | `standard_cert_rotation` | submit (auto-approved by template) → implement → PIR | Service Owner, CAB Chair |
| **Normal change** | `normal_db_upgrade` | submit → tech review → risk review → CAB decision → implement → PIR | Service Owner + 3 CAB roles |
| **Failed change** | `failed_change_rollback` | Same as Normal but `force_backout=true` exercises the rollback path | Service Owner + 3 CAB roles |

## Six named context layers

Earlier versions of this project passed strings between tasks via CrewAI's `context=[task1, task2]` parameter. That worked for incident handoff but it's not what ITIL means by "context." Tools now read from and write to six shared, queryable layers in `src/state.py`:

| Layer | Holds | Mutable? |
|---|---|---|
| `services` | Service catalog: RTO/RPO, dependencies, compliance, DR strategy | mostly read |
| `cmdb` | Configuration Items, relationships, owners, current state | yes — `update()` attributes changes to a `change_id` |
| `calendar` | All `ChangeRecord` objects, scheduled windows, freeze windows, standard templates | yes — RFCs flow through here |
| `policy` | Regulatory frameworks → impacted controls per CI tag | static |
| `operations` | Active incidents, on-call roster, monitoring snapshot | yes |
| `kedb` | Known Error Database — past failures drive risk scoring | yes — failed changes auto-create entries |

Within one `python main.py` run the layers are module-level singletons, so an RFC submitted by one agent is visible to the reviewer agent on the next task.

## Change record lifecycle

`ChangeRecord` (in `src/models.py`) is an explicit ITIL state machine. Allowed transitions live in `ALLOWED_TRANSITIONS` and are enforced by `ChangeCalendarLayer.transition()` — agents can't teleport states.

```
DRAFT
  ↓
SUBMITTED ─────────────────────────────► REJECTED ──► CLOSED
  ↓
UNDER_TECHNICAL_REVIEW
  ↓
UNDER_RISK_REVIEW
  ↓
AT_CAB
  ↓
APPROVED
  ↓
SCHEDULED ──► IN_PROGRESS ──► IMPLEMENTED ──► CLOSED
                            └─► FAILED ──► BACKED_OUT ──► CLOSED
```

Standard changes auto-promote SUBMITTED → APPROVED inside `submit_rfc` when a `standard_template_id` is provided.

## Agents

Indices are stable and used by tasks to bind:

| # | Role | Key change-management tools |
|---|---|---|
| 0 | Incident Classification Specialist | — |
| 1 | Business Impact Analyst | — |
| 2 | Recovery Engineer | `submit_rfc`, `execute_change`, `update_cmdb` (emergency changes during DR) |
| 3 | Stakeholder Communicator | — |
| 4 | Security Operations Analyst | `submit_rfc` (emergency containment changes) |
| 5 | Service Owner / Change Requester | `submit_rfc`, `execute_change`, `update_cmdb`, `query_change_calendar`, `query_kedb` |
| 6 | Technical Reviewer (CAB) | `review_rfc_technical`, `query_kedb`, `query_cmdb` |
| 7 | Risk & Compliance Reviewer (CAB) | `review_rfc_risk`, `query_kedb`, `query_change_calendar`, `check_compliance_status` |
| 8 | CAB Chair / Change Manager | `cab_decision`, `schedule_change`, `conduct_pir`, `promote_to_standard` |

The previous monolithic "Change & Release Manager" was split into agents 6, 7, and 8 to enforce segregation of duties: the requester is not the implementer is not the reviewer is not the approver.

## Change-management tools

Defined in `src/change_tools.py`. Each tool returns JSON and mutates the relevant context layer.

| Tool | Owner role | Effect |
|---|---|---|
| `submit_rfc` | Service Owner / Recovery / SecOps | Creates `ChangeRecord` in `calendar`; auto-approves if standard template |
| `review_rfc_technical` | Technical Reviewer | Records four-check (impl plan, backout, test evidence, CIs); transitions to UNDER_RISK_REVIEW or REJECTED |
| `review_rfc_risk` | Risk & Compliance Reviewer | Computes `risk_score = probability × impact / 100`; queries KEDB; checks calendar + freeze; identifies required approvers |
| `cab_decision` | CAB Chair | Records voting members, conditions, rationale; transitions to APPROVED or REJECTED |
| `schedule_change` | CAB Chair | Re-validates window; transitions to SCHEDULED or returns conflicts |
| `execute_change` | Implementer | Pre-checks → CMDB updates (attributed to change_id) → post-checks; `force_backout=true` exercises the rollback path |
| `update_cmdb` | Implementer | Direct CMDB mutation with change attribution |
| `query_change_calendar` | Service Owner / Risk Reviewer | Returns window collisions on shared CIs + active freeze windows |
| `query_kedb` | All reviewers | Returns Known Error Database entries matching CI / symptom |
| `conduct_pir` | CAB Chair | Records objective_met, side effects, lessons, remediation items; transitions to CLOSED; failed changes seed new KEDB entries |
| `promote_to_standard` | CAB Chair | Promotes a clean run into a pre-approved template so future identical changes skip full CAB |

## Scenarios

Set `EVENT_SCENARIO` in `main.py`:

| Scenario | Category | What it exercises |
|---|---|---|
| `ransomware` | incident | LockBit encryption — full incident response + emergency CAB |
| `cloud_outage_ddos` | incident | AWS regional outage + DDoS — full incident response |
| `data_breach` | incident | 2.3M records exfiltrated — GDPR 72h deadline |
| `insider_threat` | incident | Privileged DBA exfiltration — forensic preservation |
| `supply_chain` | incident | PayBridge compromise — vendor coordination |
| `cascading_failure` | incident | Failed DB migration — recovery + change mgmt |
| `standard_cert_rotation` | standard | Pre-approved cert rotation — uses STD-CERT-001 template; auto-approves |
| `normal_db_upgrade` | normal | PostgreSQL minor upgrade — full CAB review; agents must avoid month-end freeze (2026-04-28 to 2026-04-30) |
| `failed_change_rollback` | failed | API gateway deploy that fails post-checks — exercises BACKED_OUT path and KEDB feedback loop |

## Scoring

`simulation_engine.py` evaluates against eight dimensions; weights vary by scenario.

**Keyword-based** (text of agent outputs):

1. Incident Classification
2. Business Impact Analysis
3. Security Containment
4. Disaster Recovery
5. Change Management
6. Stakeholder Communication
7. Regulatory Compliance

**Artifact-based** (reads `state.calendar`, `state.cmdb`):

8. **Change Governance** — checks that the lifecycle was actually followed:
   - Did changes reach a terminal state (IMPLEMENTED / BACKED_OUT / CLOSED)?
   - Was the CMDB updated with `change_id` attribution?
   - Were proper artifacts produced for the change category?
     - **Standard:** template used, auto-approval traversed, PIR conducted
     - **Normal:** technical review present, risk review with KEDB references, CAB decision with voting members matching the required approver chain, calendar checked
     - **Emergency:** abbreviated tech + risk reviews, CAB decision, linked incident_id, PIR
   - Did PIR produce remediation items with owner + due date + priority?

The artifact-based dimension means agents can't earn governance points just by mentioning ITIL words — the underlying state machine must actually have transitioned correctly.

## Frameworks practiced

NIST CSF, MITRE ATT&CK, ITIL 4 Service Continuity & Change Enablement, ISO 22301, FFIEC BCM Handbook, PCI-DSS, SOX, GDPR.

## Project structure

```
├── main.py                  # Entry point — select scenario, run crew, auto-grade
├── simulation_engine.py     # 8-dimension scoring (7 keyword + 1 artifact-based)
├── requirements.txt
├── scripts/
│   └── smoke_test.py        # Drives the lifecycle without an LLM (fast)
├── src/
│   ├── agents.py            # 9 agents (5 incident + 1 service owner + 3 CAB roles)
│   ├── tasks.py             # INCIDENT_TASKS / NORMAL_CHANGE_TASKS / STANDARD_CHANGE_TASKS
│   ├── bcm_crew.py          # Crew factory; branches on scenario category
│   ├── tools.py             # Existing 13 incident-response tools (now read from state layers)
│   ├── change_tools.py      # 11 change-management tools (submit/review/CAB/schedule/execute/PIR)
│   ├── models.py            # ChangeRecord, ChangeState, RiskLevel, PIRRecord, etc.
│   └── state.py             # 6 named context layers as singletons
```

## Setup

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) running locally with `qwen3:8b-q4_K_M`

### Installation

```bash
git clone https://github.com/cocheuno/itsm-devops-bcm-crewai-starter.git
cd itsm-devops-bcm-crewai-starter
pip install -r requirements.txt
ollama pull qwen3:8b-q4_K_M
```

### Run

```bash
python main.py
```

Edit `EVENT_SCENARIO` in `main.py` to switch scenarios.

### Validate without an LLM

`scripts/smoke_test.py` drives the change-tools through their lifecycle directly and runs the simulation engine against the resulting state — fast confirmation that the state machine and scoring are wired correctly:

```bash
python scripts/smoke_test.py
```

### Switching the LLM

Edit `ollama_llm` in `src/agents.py`:

```python
ollama_llm = LLM(
    model="ollama/qwen3:8b-q4_K_M",
    base_url="http://localhost:11434",
    timeout=1200,
)
```

For Groq or OpenAI, replace with `LLM(model="groq/...")` or `LLM(model="gpt-...")` and set the appropriate API key in a `.env` file.
