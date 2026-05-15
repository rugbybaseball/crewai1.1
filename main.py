"""
Software License Approval Router — Service Request Fulfillment Agent
====================================================================

PHASE 2 DELIVERABLE — one agent, one decision, deterministic gates, falsifiable
success criteria. This entry point exists for exactly one purpose: drive a
software-license ServiceNow ticket through the License Approval Router and
grade the run with measurable artifact checks.

--------------------------------------------------------------------------------
1. SCOPE — the single decision moment
--------------------------------------------------------------------------------

  Trigger:  Employee submits a ServiceNow ticket requesting a paid software license
  Agent:    license_approval_router_agent — src/agents.py idx 9
  Stop:     Ticket reaches ONE of two terminal statuses (and nothing more):
              - "Provisioning Triggered"    -> ChangeState.IMPLEMENTED, decision=auto_approve
              - "Pending Manager Approval"  -> ChangeState.UNDER_RISK_REVIEW,
                                               pending_manager_approval=True

  Out of scope (deliberately): the manager's eventual decision, real SaaS API
  provisioning, license harvest/reclaim, vendor true-up reconciliation, CSAT
  measurement. The agent STOPS at routing.

--------------------------------------------------------------------------------
2. DECISION LOGIC — three gates + two hard guards
--------------------------------------------------------------------------------

The router auto-approves ONLY if ALL of these pass. Any single failure routes
the ticket to a manager. Implemented deterministically in
src/change_tools.py::RouteLicenseRequestTool — no LLM judgment on the math.

  Gate 1  cost            annual_cost <= $500 (state.license_catalog.AUTO_APPROVE_COST_THRESHOLD)
  Gate 2  role_match      requester_role in SKU's eligible_roles (or wildcard '*')
  Gate 3  budget          department headroom covers the annual_cost
  Guard A enterprise_cap  (HARD) seats_in_use + requested seats <= ELA cap
  Guard B circuit_breaker (HARD) department spend hasn't breached 110% of forecast

--------------------------------------------------------------------------------
3. STAKEHOLDERS WITH CONFLICTING INTERESTS (from Phase 1 Problem Discovery)
--------------------------------------------------------------------------------

  End User          wants speed         -> harmed by a conservative router that
                                          escalates everything; portal feels useless
  IT Finance        wants budget control -> harmed by a permissive router that
                                          auto-approves expensive specialist tools
  IT Service Desk   wants low queue     -> harmed by EITHER failure mode (escalation
                                          floods queue OR auto-approve floods complaints)

The router is designed to err toward routing-to-human when ANY gate fails — the
asymmetric cost of an unwanted $1,000 license vs the cost of an extra manager
ping justifies this default.

--------------------------------------------------------------------------------
4. HONEST FAILURE MODES (the agent must own these)
--------------------------------------------------------------------------------

  False auto-approve   ($1,000 IDE auto-approved for a non-developer)
                       -> IT Finance political fallout, ELA budget burn.
                       Mitigated by: role_match gate.

  False escalation     ($20 collaboration license routed to manager)
                       -> CSAT collapse, manager-time waste.
                       Mitigated by: explicit '*' wildcard on universally-eligible SKUs
                       so cheap+universal items auto-approve.

  ELA true-up (2nd-order) (auto-approve pushes SKU over enterprise license cap)
                       -> Real vendor invoice in production; legal/procurement exposure.
                       Mitigated by: enterprise_cap HARD guard — escalates regardless
                       of cost.

  Blanket freeze (2nd-order) (cumulative auto-approved spend overruns budget)
                       -> Finance freezes ALL automated approvals → service desk
                       buried in backlog → the whole automation gets killed.
                       Mitigated by: circuit_breaker HARD guard — once department
                       spend exceeds 110% of forecast, ALL further requests route to
                       manual until reset.

--------------------------------------------------------------------------------
5. FALSIFIABLE SUCCESS CRITERIA (graded mechanically post-run)
--------------------------------------------------------------------------------

simulation_engine.py::_score_service_request_artifacts inspects state.service_requests,
state.calendar, and state.cmdb after the run and scores six bands totaling 100:

   25 pts  every request reached a terminal routing status
   25 pts  100% of >$500/seat-year requests routed to manager (any violation = 0)
   15 pts  every decision recorded a complete gate_results list (audit-grade)
   15 pts  auto-approved requests left CMDB allocation + budget charge
   10 pts  median routing latency < 3000 ms (Phase 1 SLA proxy)
   10 pts  no hard-guard breaches on auto-approved requests

A run passes the Phase 1 falsifiable check iff service_request_governance_score >= 80.

--------------------------------------------------------------------------------
6. RUN
--------------------------------------------------------------------------------

  $ python main.py                            # runs default fixture (route-to-manager)
  Edit LICENSE_REQUEST_FIXTURE below to switch.

  $ python scripts/smoke_test.py              # exercises all 4 fixtures without an LLM
"""
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from src.bcm_crew import create_bcm_crew, category_for_scenario
from simulation_engine import SimulationEngine


# ---------------------------------------------------------------------------
# Pick the ServiceNow ticket fixture to drive into the router.
#
# All five fixtures invoke the SAME agent (license_approval_router_agent)
# and the SAME single decision moment. They differ only in the request
# payload, which stresses different gates. This is intentional — Phase 1
# scope says ONE decision, ONE agent.
#
#   adobe_cc_designer    $720  designer/design       -> manager  (cost gate)
#   zoom_engineer        $150  engineer/engineering  -> auto-approve
#   salesforce_designer  $1800 designer/design       -> manager  (role gate + cost)
#   jetbrains_developer  $1000 developer/engineering -> manager  (cost gate)
#   acrobat_anyone       $180  marketing/marketing   -> auto-approve
# ---------------------------------------------------------------------------

LICENSE_REQUEST_FIXTURE = "adobe_cc_designer"


LICENSE_REQUESTS = {
    "adobe_cc_designer": {
        "ticket_id": "REQ0010472",
        "requester": "jordan.lee@finserve.com",
        "requester_role": "designer",
        "department": "design",
        "license_sku": "ADOBE-CC-FULL",
        "seats": 1,
        "business_justification": (
            "Need Creative Cloud full suite for the FinServe-2026 rebrand assets "
            "(Photoshop, Illustrator, After Effects). Current Acrobat-only seat "
            "is insufficient for vector / motion work."
        ),
        "expected_outcome": "route_to_manager  (cost $720 > $500 threshold)",
        "stresses_gate": "cost",
    },
    "zoom_engineer": {
        "ticket_id": "REQ0010558",
        "requester": "taylor.kim@finserve.com",
        "requester_role": "engineer",
        "department": "engineering",
        "license_sku": "ZOOM-PRO",
        "seats": 1,
        "business_justification": (
            "Replacement seat — previous user offboarded. Required for on-call "
            "bridge calls and customer escalation video sessions."
        ),
        "expected_outcome": "auto_approve  (all gates pass)",
        "stresses_gate": "happy path",
    },
    "salesforce_designer": {
        "ticket_id": "REQ0010613",
        "requester": "rene.ng@finserve.com",
        "requester_role": "designer",
        "department": "design",
        "license_sku": "SALESFORCE-CRM-ENT",
        "seats": 1,
        "business_justification": (
            "Want access to view sales pipeline data for upcoming brand campaign."
        ),
        "expected_outcome": "route_to_manager  (role 'designer' not in eligible_roles)",
        "stresses_gate": "role_match",
    },
    "jetbrains_developer": {
        "ticket_id": "REQ0010744",
        "requester": "sam.dev@finserve.com",
        "requester_role": "developer",
        "department": "engineering",
        "license_sku": "JETBRAINS-IDEA-ULT",
        "seats": 1,
        "business_justification": (
            "Need IntelliJ Ultimate for Spring Boot work on the payments service."
        ),
        "expected_outcome": "route_to_manager  (cost $1000 > $500 threshold)",
        "stresses_gate": "cost (eligible role, but expensive specialist tool)",
    },
    "acrobat_anyone": {
        "ticket_id": "REQ0010801",
        "requester": "alex.mktg@finserve.com",
        "requester_role": "marketing",
        "department": "marketing",
        "license_sku": "ADOBE-ACROBAT-STD",
        "seats": 1,
        "business_justification": (
            "PDF redaction & signature workflow for vendor contract review."
        ),
        "expected_outcome": "auto_approve  (all gates pass)",
        "stresses_gate": "happy path (cheap + wildcard role)",
    },
}


def _format_servicenow_ticket(req: dict) -> str:
    """Render the request as a ServiceNow-style ticket the agent ingests."""
    return (
        "================ ServiceNow Software License Request ================\n"
        f"  Ticket ID:        {req['ticket_id']}\n"
        f"  Requester:        {req['requester']}\n"
        f"  Requester role:   {req['requester_role']}\n"
        f"  Department:       {req['department']}\n"
        f"  License SKU:      {req['license_sku']}\n"
        f"  Seats:            {req['seats']}\n"
        f"  Business need:    {req['business_justification']}\n"
        "======================================================================\n\n"
        "AGENT INSTRUCTIONS — License Approval Router\n"
        "--------------------------------------------\n"
        "You are the Software License Approval Router. This ticket is the ONLY\n"
        "decision moment you are responsible for. Apply the deterministic gates\n"
        "and stop. Do NOT call any tools beyond the four listed below.\n\n"
        "Required tool sequence:\n"
        "  1. query_license_catalog(sku=<license_sku>)\n"
        "       -> read cost_per_seat_year, eligible_roles, enterprise_cap,\n"
        "          seats_in_use, template_id, compliance_tags.\n"
        "  2. check_budget(department=<department>, cost=<annual_cost>)\n"
        "       -> read headroom, would_overrun, circuit_breaker_active.\n"
        "  3. submit_license_request(requester=..., requester_role=...,\n"
        "          department=..., license_sku=..., seats=...)\n"
        "       -> creates paired ChangeRecord + LicenseRequestRecord;\n"
        "          returns request_id and change_id. Capture both.\n"
        "  4. route_license_request(request_id=<request_id>)\n"
        "       -> THE DECISION MOMENT. Applies all 3 gates + 2 hard guards,\n"
        "          transitions the ChangeRecord state, writes the CMDB\n"
        "          allocation (auto-approve) OR flips pending_manager_approval\n"
        "          (manager path). Returns full gate_results and latency_ms.\n\n"
        "STOP after step 4. The manager-side decision is out of scope.\n\n"
        "Hard constraints you must NEVER violate:\n"
        "  - NEVER auto-approve when ANY gate fails — route to manager.\n"
        "  - NEVER auto-approve if enterprise_cap would be exceeded, regardless\n"
        "    of cost (this prevents vendor true-up audits).\n"
        "  - NEVER auto-approve if the department circuit_breaker is active\n"
        "    (this prevents a repeat of the 2025-Q3 budget-overrun incident\n"
        "    that caused IT Finance to freeze ALL automated approvals).\n\n"
        "Terminal states (one of these must be reached, nothing else):\n"
        "  AUTO-APPROVE PATH:\n"
        "    SUBMITTED -> UNDER_TECHNICAL_REVIEW -> UNDER_RISK_REVIEW -> AT_CAB\n"
        "    -> APPROVED -> IN_PROGRESS -> IMPLEMENTED\n"
        "    + CMDB allocation entry written with change_id attribution\n"
        "    + Budget charged; SKU seats reserved\n\n"
        "  MANAGER PATH:\n"
        "    SUBMITTED -> UNDER_TECHNICAL_REVIEW -> UNDER_RISK_REVIEW\n"
        "    + pending_manager_approval = true\n"
        "    + gate_results recorded with audit-grade reasons"
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

SCENARIO = "software_license_request"

if LICENSE_REQUEST_FIXTURE not in LICENSE_REQUESTS:
    raise ValueError(
        f"Unknown fixture '{LICENSE_REQUEST_FIXTURE}'. "
        f"Pick one of: {sorted(LICENSE_REQUESTS.keys())}"
    )

request = LICENSE_REQUESTS[LICENSE_REQUEST_FIXTURE]
event_description = _format_servicenow_ticket(request)
category = category_for_scenario(SCENARIO)

print("=" * 80)
print("📨 SERVICE REQUEST FULFILLMENT — Software License Approval Router")
print("   Phase 2 Deliverable | Agent: license_approval_router_agent (idx 9)")
print("=" * 80)
print(f"  Fixture            : {LICENSE_REQUEST_FIXTURE}")
print(f"  ServiceNow Ticket  : {request['ticket_id']}")
print(f"  SKU                : {request['license_sku']} ({request['seats']} seat(s))")
print(f"  Requester          : {request['requester']}")
print(f"  Role / Department  : {request['requester_role']} / {request['department']}")
print(f"  Gate stressed      : {request['stresses_gate']}")
print(f"  Expected outcome   : {request['expected_outcome']}")
print(f"  Scenario category  : {category}")
print("=" * 80)
print()
print(event_description)
print()
print("=" * 80)
print("Activating Service Request Fulfillment crew  "
      "(Service Owner intake → License Approval Router decision)...")
print("=" * 80)
print()

crew = create_bcm_crew(SCENARIO)
result = crew.kickoff(inputs={"event_description": event_description})

print("\n" + "=" * 80)
print("ROUTER OUTPUT")
print("=" * 80)
print(result)
print("=" * 80)

engine = SimulationEngine()
score = engine.evaluate(result, SCENARIO)

print(f"\n🎯 OVERALL KPI SCORE: {score['overall_kpi_score']}%")
print("📊 Detailed Scoring:")
for key, value in score.items():
    if key != "overall_kpi_score":
        print(f"   {key}: {value}")

# Phase 1 falsifiable verdict — the only criterion that defines a PASS.
sr_score = score.get("service_request_governance_score")
if sr_score is not None:
    verdict = "PASS" if sr_score >= 80 else "FAIL"
    print()
    print("=" * 80)
    print(f"🔬 PHASE 1 FALSIFIABLE CRITERIA  →  service_request_governance = "
          f"{sr_score}/100  →  {verdict}")
    print("=" * 80)
    if verdict == "FAIL":
        print(
            "Check the run log for: missing gate_results, terminal state not reached,\n"
            "expensive request that slipped past the cost gate, CMDB allocation not\n"
            "written on auto-approve, or hard-guard breach. See\n"
            "simulation_engine.py::_score_service_request_artifacts for band-by-band logic."
        )
