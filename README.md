# Service Request Fulfillment — Software License Approval Router

**Phase 2 deliverable** — a single-decision CrewAI agent that auto-approves or routes a software-license ServiceNow ticket to a manager, with falsifiable success criteria graded mechanically from the run's artifacts.

Backed by a fictional digital bank ("FinServe") and a local Ollama LLM. The same repo also contains two adjacent ITSM flows (incident-driven business continuity and planned ITIL change management) that share the underlying state layers and CAB scaffolding, but the **headline deliverable, the agent under test, and the entry point ([main.py](main.py)) are 100% focused on Service Request Fulfillment for software licenses**.

| Flow | Purpose |
|---|---|
| **Service Request Fulfillment — License Approval** *(Phase 2 — headline)* | Auto-approve OR route-to-manager for a single license ServiceNow ticket |
| Incident-driven business continuity *(regression)* | Ransomware / data breach / cascading failure scenarios — exercised by `scripts/smoke_test.py` |
| Planned ITIL change management *(regression)* | Standard / normal / failed-rollback CAB lifecycle — exercised by `scripts/smoke_test.py` |

## What's modeled

The crew runs in one of three flow shapes selected by the scenario:

| Flow | When it runs | Tasks | Agents that participate |
|---|---|---|---|
| **Service Request — License Approval** *(Phase 2)* | `software_license_request` | intake → routing decision | Service Owner (idx 5), License Approval Router (idx 9) |
| **Incident response** (with emergency CAB) | One of the 6 incident scenarios | classify → BIA → contain → recover → emergency CAB → comms | Detection, Impact, SecOps, Recovery, Comms + the 3 CAB roles |
| **Standard change** | `standard_cert_rotation` | submit (auto-approved by template) → implement → PIR | Service Owner, CAB Chair |
| **Normal change** | `normal_db_upgrade` | submit → tech review → risk review → CAB decision → implement → PIR | Service Owner + 3 CAB roles |
| **Failed change** | `failed_change_rollback` | Same as Normal but `force_backout=true` exercises the rollback path | Service Owner + 3 CAB roles |

## Phase 2 — Software License Approval Router

### The single decision moment under test

- **Trigger:** Employee submits a ServiceNow ticket requesting a paid software license
- **Agent under test:** `license_approval_router_agent` ([src/agents.py](src/agents.py) idx 9)
- **Stop:** Ticket reaches one of two terminal statuses:
  - `Provisioning Triggered` (auto-approved, `IMPLEMENTED`)
  - `Pending Manager Approval` (`UNDER_RISK_REVIEW` + `pending_manager_approval=true`)

### Three deterministic gates + two hard guards

The router applies these in order, every time, against `state.license_catalog` and `state.budget`:

| # | Gate | Auto-approve only if... |
|---|---|---|
| 1 | **cost** | `annual_cost <= $500` (the Phase 1 threshold) |
| 2 | **role_match** | requester role ∈ SKU's `eligible_roles` (or `*` wildcard) |
| 3 | **budget** | department headroom covers the annual_cost |
| H | **enterprise_cap** *(hard guard)* | `seats_in_use + requested <= ELA cap` — fails the routing regardless of cost |
| H | **circuit_breaker** *(hard guard)* | department spend has not breached 110% of monthly forecast |

Any gate or guard failure routes the request to a manager. No keyword matching, no LLM judgment on the gate logic — the agent calls `route_license_request`, which is the deterministic implementation.

### Falsifiable success criteria

`simulation_engine.py::_score_service_request_artifacts` reads the resulting artifacts (`state.service_requests`, `state.calendar`, `state.cmdb`) and scores six bands totaling 100:

| Points | Check |
|---|---|
| 25 | Every request reached a terminal routing status |
| 25 | 100% of >$500/seat/year requests routed to manager *(any single violation = 0 on this band)* |
| 15 | Every decision recorded a complete `gate_results` list |
| 15 | Auto-approved requests left a CMDB allocation entry + budget charge |
| 10 | Median routing latency < 3000 ms |
| 10 | No hard-guard breaches on auto-approved requests |

The Phase 2 weighting in `_calculate_overall_score`: `service_request_governance` = 60%, `change_management` = 20%, `regulatory_compliance` = 20%.

### Built-in fixtures

Edit `LICENSE_REQUEST_FIXTURE` in [main.py](main.py) to pick the scenario:

| Fixture | SKU | Cost | Role | Expected outcome |
|---|---|---|---|---|
| `adobe_cc_designer` *(default)* | ADOBE-CC-FULL | $720 | designer / design | route to manager (cost gate) |
| `zoom_engineer` | ZOOM-PRO | $150 | engineer / eng | auto-approve |
| `salesforce_designer` | SALESFORCE-CRM-ENT | $1800 | designer / design | route to manager (role gate) |
| `jetbrains_developer` | JETBRAINS-IDEA-ULT | $1000 | developer / eng | route to manager (cost gate) |
| `acrobat_anyone` | ADOBE-ACROBAT-STD | $180 | marketing / marketing | auto-approve |

## Nine named context layers

Tools read from and write to nine shared, queryable layers in [src/state.py](src/state.py):

| Layer | Holds | Used by |
|---|---|---|
| `services` | Service catalog: RTO/RPO, dependencies, compliance, DR strategy | incident flow |
| `cmdb` | Configuration Items, relationships, owners, current state | all flows |
| `calendar` | All `ChangeRecord` objects, windows, freeze windows, standard templates | all flows |
| `policy` | Regulatory frameworks → impacted controls per CI tag | all flows |
| `operations` | Active incidents, on-call roster, monitoring snapshot | incident flow |
| `kedb` | Known Error Database — past failures drive risk scoring | change flow |
| `license_catalog` *(Phase 2)* | License SKUs: cost, eligible_roles, enterprise_cap, compliance_tags | service request flow |
| `budget` *(Phase 2)* | Department monthly pools, spend ledger, circuit breaker | service request flow |
| `service_requests` *(Phase 2)* | `LicenseRequestRecord` registry linking to ChangeRecord | service request flow |

Within one `python main.py` run the layers are module-level singletons, so an RFC submitted by one agent is visible to the reviewer agent on the next task.

## Change record lifecycle

`ChangeRecord` (in [src/models.py](src/models.py)) is an explicit ITIL state machine. Allowed transitions live in `ALLOWED_TRANSITIONS` and are enforced by `ChangeCalendarLayer.transition()` — agents can't teleport states.

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

Standard changes auto-promote SUBMITTED → APPROVED inside `submit_rfc` when a `standard_template_id` is provided. The Phase 2 router walks the full state machine explicitly on auto-approval (SUBMITTED → UNDER_TECHNICAL_REVIEW → UNDER_RISK_REVIEW → AT_CAB → APPROVED → IN_PROGRESS → IMPLEMENTED) so the artifact trail is complete and auditable.

## Agents

Indices are stable and used by tasks to bind:

| # | Role | Key tools |
|---|---|---|
| 0 | Incident Classification Specialist | — |
| 1 | Business Impact Analyst | — |
| 2 | Recovery Engineer | `submit_rfc`, `execute_change`, `update_cmdb` (emergency changes during DR) |
| 3 | Stakeholder Communicator | — |
| 4 | Security Operations Analyst | `submit_rfc` (emergency containment changes) |
| 5 | Service Owner / Change Requester | `submit_rfc`, `execute_change`, `update_cmdb`, `query_change_calendar`, `query_kedb`, `submit_license_request` |
| 6 | Technical Reviewer (CAB) | `review_rfc_technical`, `query_kedb`, `query_cmdb` |
| 7 | Risk & Compliance Reviewer (CAB) | `review_rfc_risk`, `query_kedb`, `query_change_calendar`, `check_compliance_status` |
| 8 | CAB Chair / Change Manager | `cab_decision`, `schedule_change`, `conduct_pir`, `promote_to_standard` |
| 9 | **Software License Approval Router** *(Phase 2)* | `query_license_catalog`, `check_budget`, `submit_license_request`, `route_license_request`, `query_cmdb`, `query_change_calendar` |

The previous monolithic "Change & Release Manager" was split into agents 6, 7, and 8 to enforce segregation of duties: the requester is not the implementer is not the reviewer is not the approver.

## Tools

Defined in [src/change_tools.py](src/change_tools.py). Each tool returns JSON and mutates the relevant context layer.

### Change-management tools

| Tool | Owner role | Effect |
|---|---|---|
| `submit_rfc` | Service Owner / Recovery / SecOps | Creates `ChangeRecord` in `calendar`; auto-approves if standard template |
| `review_rfc_technical` | Technical Reviewer | Records four-check; transitions to UNDER_RISK_REVIEW or REJECTED |
| `review_rfc_risk` | Risk & Compliance Reviewer | Computes `risk_score = probability × impact / 100`; queries KEDB; checks calendar + freeze |
| `cab_decision` | CAB Chair | Records voting members, conditions, rationale; transitions to APPROVED or REJECTED |
| `schedule_change` | CAB Chair | Re-validates window; transitions to SCHEDULED |
| `execute_change` | Implementer | Pre-checks → CMDB updates → post-checks; `force_backout=true` exercises rollback |
| `update_cmdb` | Implementer | Direct CMDB mutation with change attribution |
| `query_change_calendar` | Service Owner / Risk Reviewer | Returns window collisions + active freeze windows |
| `query_kedb` | All reviewers | Returns KEDB entries matching CI / symptom |
| `conduct_pir` | CAB Chair | Records objective_met, side effects, lessons, remediation items; transitions to CLOSED |
| `promote_to_standard` | CAB Chair | Promotes a clean run into a pre-approved template |

### Phase 2 — Service Request tools

| Tool | Owner role | Effect |
|---|---|---|
| `query_license_catalog` | License Router | Returns SKU metadata: cost, eligible_roles, enterprise_cap, seats_in_use, compliance_tags |
| `check_budget` | License Router | Returns department headroom + `would_overrun` flag + `circuit_breaker_active` flag |
| `submit_license_request` | Service Owner | Creates paired `ChangeRecord` + `LicenseRequestRecord` (category=software_license, state=SUBMITTED) |
| `route_license_request` | License Router | **THE single decision moment.** Applies 3 gates + 2 hard guards. Auto-approves OR routes to manager. Records `gate_results`, `decision`, `latency_ms`. |

## Scenarios

Set `LICENSE_REQUEST_FIXTURE` in [main.py](main.py) to pick a service-request variant. Incident/change scenarios are exercised by [scripts/smoke_test.py](scripts/smoke_test.py) (no LLM needed for those).

| Scenario | Category | What it exercises |
|---|---|---|
| `software_license_request` ★ *(Phase 2 default)* | service_request | License Approval Router — single decision moment |
| `ransomware` | incident | LockBit encryption — full incident response + emergency CAB |
| `cloud_outage_ddos` | incident | AWS regional outage + DDoS |
| `data_breach` | incident | 2.3M records exfiltrated — GDPR 72h deadline |
| `insider_threat` | incident | Privileged DBA exfiltration |
| `supply_chain` | incident | PayBridge compromise |
| `cascading_failure` | incident | Failed DB migration |
| `standard_cert_rotation` | standard | Pre-approved cert rotation — STD-CERT-001 template |
| `normal_db_upgrade` | normal | PostgreSQL minor upgrade — full CAB review |
| `failed_change_rollback` | failed | API gateway deploy that fails post-checks — exercises BACKED_OUT path |

## Scoring

[simulation_engine.py](simulation_engine.py) evaluates against nine dimensions; weights vary by scenario.

**Keyword-based** (text of agent outputs):
1. Incident Classification
2. Business Impact Analysis
3. Security Containment
4. Disaster Recovery
5. Change Management
6. Stakeholder Communication
7. Regulatory Compliance

**Artifact-based** (reads `state.calendar`, `state.cmdb`, `state.service_requests`):

8. **Change Governance** — checks the change lifecycle was actually followed (terminal state, CMDB attribution, proper artifacts per change category, PIR remediation items)
9. **Service Request Governance** *(Phase 2)* — six falsifiable bands listed above; the headline grade for the License Approval Router

The artifact-based dimensions mean agents can't earn governance points just by mentioning ITIL words — the underlying state machine must actually have transitioned correctly.

## Frameworks practiced

NIST CSF, MITRE ATT&CK, ITIL 4 Service Continuity & Change Enablement, ITIL 4 Service Request Management, ISO 22301, FFIEC BCM Handbook, PCI-DSS, SOX, GDPR.

## Project structure

```
├── main.py                  # Entry point — License Approval Router by default
├── simulation_engine.py     # 9-dimension scoring (7 keyword + 2 artifact-based)
├── requirements.txt
├── scripts/
│   └── smoke_test.py        # Drives every flow (incident, change, license) without an LLM
├── src/
│   ├── agents.py            # 10 agents (idx 0-9; idx 9 = License Approval Router)
│   ├── tasks.py             # INCIDENT_TASKS / NORMAL_CHANGE_TASKS / STANDARD_CHANGE_TASKS /
│   │                        # FAILED_CHANGE_TASKS / SERVICE_REQUEST_TASKS
│   ├── bcm_crew.py          # Crew factory; branches on scenario category
│   ├── tools.py             # Incident-response tools (read from state layers)
│   ├── change_tools.py      # Change-mgmt tools + 4 license tools (Phase 2)
│   ├── models.py            # ChangeRecord, ChangeState, LicenseRequestRecord, GateResult, etc.
│   └── state.py             # 9 named context layers as singletons
```

## Setup

### Prerequisites

- **Python 3.11** (recommended — 3.13/3.14 lack pre-built wheels for `tiktoken` and friends)
- [Ollama](https://ollama.com/) running locally with `qwen3:8b-q4_K_M`

### Installation

```bash
git clone https://github.com/rugbybaseball/CrewAI_Agent.git
cd CrewAI_Agent
python3.11 -m venv venv
source venv/bin/activate           # Windows: venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
ollama pull qwen3:8b-q4_K_M
```

If `python3.11` isn't installed on macOS: `brew install python@3.11`.

### Run the Phase 2 License Approval Router

```bash
python main.py
```

This runs the default fixture (`adobe_cc_designer` → expected to route to manager). To exercise the auto-approve path, edit [main.py:50](main.py) and set:

```python
LICENSE_REQUEST_FIXTURE = "zoom_engineer"
```

Other fixtures: `salesforce_designer`, `jetbrains_developer`, `acrobat_anyone`.

### Validate without an LLM

[scripts/smoke_test.py](scripts/smoke_test.py) drives every flow (incident change-mgmt, standard, failed-rollback, and all four license fixtures) directly and runs the simulation engine against the resulting state — fast confirmation that the state machines and scoring are wired correctly:

```bash
python scripts/smoke_test.py
```

Expected: `ALL SMOKE TESTS PASSED ✓` and `service_request_governance_score = 100`.

### What to look for in the live LLM run

For the default `adobe_cc_designer` fixture:

- Intake task returns JSON containing `"state": "submitted"`, `"annual_cost": 720.0`
- Routing task returns the `LicenseRequestRecord` with `"decision": "route_to_manager"`, `"pending_manager_approval": true`, and a `gate_results` list showing `cost: FAIL`, `role_match: PASS`, `budget: PASS`
- Final score line: `✅ Service Request Governance.............. ██████████ 100/100`
- Final PASS/FAIL: `🔬 Phase 1 falsifiable criteria: service_request_governance = 100/100 -> PASS`

### Switching the LLM

Edit `ollama_llm` in [src/agents.py](src/agents.py):

```python
ollama_llm = LLM(
    model="ollama/qwen3:8b-q4_K_M",
    base_url="http://localhost:11434",
    timeout=1200,
)
```

For Groq or OpenAI, replace with `LLM(model="groq/...")` or `LLM(model="gpt-...")` and set the appropriate API key in a `.env` file.
