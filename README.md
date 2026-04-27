# FinServe Digital Bank – BCM Agent Simulation (CrewAI)

Production-grade starter repo for the **Agent-Driven Business Continuity Management Challenge**. A multi-agent system that simulates real-world incident response for a fictional digital bank, powered by CrewAI and a local Ollama LLM.

## What Students Do

- Customize the **6 agents** in `src/agents.py` (roles, goals, backstories, tool assignments)
- Refine the **6 sequential tasks** in `src/tasks.py`
- Tune the **13 simulation tools** in `src/tools.py`
- Run `python main.py` when the instructor triggers a live event
- Agents automatically classify, contain, assess, recover, manage changes, and communicate
- The **simulation engine** auto-grades the response across 7 scoring dimensions

## Agents

| # | Role | Key Tools |
|---|------|-----------|
| 1 | Incident Classification Specialist | analyze_security_event, check_service_health, query_cmdb, create_incident_record |
| 2 | Business Impact Analyst | calculate_impact, check_compliance_status, assess_vendor_impact, query_cmdb |
| 3 | Recovery Engineer | check_service_health, query_cmdb, failover_service, execute_runbook, log_lesson |
| 4 | Stakeholder Communicator | send_notification, coordinate_war_room, check_compliance_status, query_cmdb |
| 5 | Security Operations (SecOps) Analyst | analyze_security_event, execute_runbook, query_cmdb, check_service_health |
| 6 | Change & Release Manager | query_cmdb, check_compliance_status, execute_runbook, log_lesson |

## Event Scenarios

The instructor selects a scenario by setting `EVENT_SCENARIO` in `main.py`:

| Scenario | Description |
|----------|-------------|
| `ransomware` | LockBit ransomware encrypts primary data center; mobile banking and transfers down |
| `cloud_outage_ddos` | AWS us-east-1 outage + multi-vector DDoS attack; payment processing at 15% |
| `data_breach` | Unauthorized access to 2.3M customer records; 47GB exfiltrated |
| `insider_threat` | Privileged DBA exporting 890GB of customer data over 3 weeks |
| `supply_chain` | Critical payment processor (PayBridge) compromised via RCE; 1.2M transactions exposed |
| `cascading_failure` | Failed database migration corrupts transaction ledger; 4 downstream systems affected |

## Scoring Engine

`simulation_engine.py` evaluates the crew's response across **7 weighted dimensions** (weights vary by scenario type):

1. **Incident Classification** — severity, MITRE ATT&CK mapping, escalation path
2. **Business Impact Analysis** — RTO/RPO, financial projections, regulatory exposure
3. **Security Containment** — IOCs, isolation, forensic evidence preservation
4. **Disaster Recovery** — failover execution, data integrity validation
5. **Change Management** — emergency CAB approval, rollback planning, audit trail
6. **Stakeholder Communication** — audience-specific messaging, channel diversity
7. **Regulatory Compliance** — NIST CSF, ITIL, ISO 22301, FFIEC, PCI-DSS, SOX, GDPR

## Frameworks Practiced

NIST CSF, MITRE ATT&CK, ITIL 4 Service Continuity, ISO 22301, FFIEC BCM Handbook, PCI-DSS, SOX, GDPR, Agent-Based Modeling principles.

## Project Structure

```
├── main.py                 # Entry point — select scenario, run crew, auto-grade
├── simulation_engine.py    # 7-dimension scoring engine
├── requirements.txt        # Python dependencies
├── src/
│   ├── agents.py           # 6 BCM agents with Ollama LLM config
│   ├── tasks.py            # 6 sequential tasks with context chaining
│   ├── bcm_crew.py         # Crew assembly (sequential process)
│   └── tools.py            # 13 simulation tools with structured Pydantic outputs
```

## Setup

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) running locally with the `qwen3:8b-q4_K_M` model

### Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/cocheuno/itsm-devops-bcm-crewai-starter.git
   cd itsm-devops-bcm-crewai-starter
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Pull the Ollama model:
   ```bash
   ollama pull qwen3:8b-q4_K_M
   ```

4. Make sure Ollama is running (`ollama serve` or the Ollama desktop app).

5. Run:
   ```bash
   python main.py
   ```

### Switching the LLM

To use a different model, edit the `ollama_llm` configuration in `src/agents.py`:

```python
ollama_llm = LLM(
    model="ollama/qwen3:8b-q4_K_M",   # change model here
    base_url="http://localhost:11434",  # Ollama default
    timeout=1200
)
```

To use Groq or OpenAI instead, replace with `LLM(model="groq/...")` or `LLM(model="gpt-...")` and set the appropriate API key in a `.env` file.