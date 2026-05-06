"""
Tasks for both incident-driven and planned change-management flows.

Two flow types are supported. bcm_crew.py picks the task list per scenario:

  INCIDENT_FLOW: classify -> bia -> contain -> recover -> emergency CAB
                 (technical review -> risk review -> decision -> PIR) -> comms

  CHANGE_FLOW (normal):   submit -> tech review -> risk review ->
                          CAB decision -> implement -> PIR

  CHANGE_FLOW (standard): submit (auto-approved by template) -> implement -> PIR

  CHANGE_FLOW (failed):   submit -> tech review -> risk review ->
                          CAB decision -> implement-with-backout -> PIR

Agent indices into create_agents() return list:
  0 detection  1 impact  2 recovery  3 comms  4 secops
  5 service_owner  6 technical_reviewer  7 risk_compliance  8 cab_chair
"""
from crewai import Task

from src.agents import create_agents

agents = create_agents()


# ============================================================================
# INCIDENT-RESPONSE TASKS
# ============================================================================

task_classify = Task(
    description=(
        "INCIDENT TRIAGE & CLASSIFICATION (NIST CSF Framework)\n\n"
        "Event: {event_description}\n\n"
        "Execute triage methodology:\n"
        "1. Call analyze_security_event to determine attack type, severity (P1-P5), MITRE ATT&CK mapping, IOCs, and blast radius\n"
        "2. Call check_service_health to assess current operational status of critical services\n"
        "3. Call query_cmdb to understand affected configuration items and dependencies\n"
        "4. Call create_incident_record to generate formal ITIL incident with priority matrix (Impact × Urgency), "
        "affected CIs, assignment group, escalation path, and BCM activation status\n\n"
        "Deliverables:\n"
        "- Incident ID and priority classification (P1-P4)\n"
        "- NIST CSF Function and Category mapping\n"
        "- MITRE ATT&CK tactic/technique if applicable\n"
        "- Affected services and configuration items\n"
        "- Initial scope assessment and blast radius estimate\n"
        "- Escalation path and BCM plan activation decision\n"
        "- Immediate containment recommendations"
    ),
    agent=agents[0],
    expected_output=(
        "Formal incident classification with ITIL 4 structure: incident ID, priority, category/subcategory, "
        "affected CIs, NIST CSF mapping, MITRE ATT&CK reference, affected service list, severity rationale, "
        "escalation path, BCM status, and recommended immediate actions"
    ),
)

task_bia = Task(
    description=(
        "BUSINESS IMPACT ANALYSIS (ISO 22301 & FFIEC Guidelines)\n\n"
        "Based on the incident from the prior task, conduct comprehensive BIA:\n"
        "1. For each affected service, call calculate_impact to model financial exposure\n"
        "2. Call check_compliance_status to identify impacted regulatory controls and notification deadlines\n"
        "3. Call assess_vendor_impact for third-party service dependencies\n\n"
        "Deliverables:\n"
        "- Prioritized recovery list (RTO-based)\n"
        "- Financial impact projection: cumulative loss per hour\n"
        "- Regulatory exposure summary with specific deadlines (GDPR 72h, PCI breach notification, etc.)\n"
        "- Vendor impact assessment and alternative vendor lead times\n"
        "- Recovery priority matrix (Impact vs Urgency)"
    ),
    agent=agents[1],
    expected_output=(
        "Business Impact Analysis report with prioritized service recovery list, financial projections, "
        "regulatory compliance impact, SLA penalty exposure, vendor impact, and executive summary."
    ),
    context=[task_classify],
)

task_contain = Task(
    description=(
        "SECURITY CONTAINMENT & EMERGENCY RFC SUBMISSION\n\n"
        "Execute containment to prevent lateral movement, preserve forensic evidence, AND submit the "
        "emergency RFC documenting your containment changes (auditors require this paper trail even "
        "during active incidents):\n"
        "1. Call analyze_security_event to identify attack scope, IOCs, and lateral movement risk\n"
        "2. Call query_cmdb to map affected systems and adjacent risks\n"
        "3. Call submit_rfc with category='emergency' to log an RFC for your containment actions. "
        "Include: title, brief description, requester (your role), implementer (likely yourself), "
        "affected_cis (comma-separated), backout_plan, and linked_incident_id from the prior task. "
        "Capture the change_id you receive — the next CAB tasks will reference it.\n"
        "4. Execute ISOLATE_NETWORK and FORENSIC_SNAPSHOT runbooks via execute_runbook\n"
        "5. Call check_service_health to monitor for lateral movement\n\n"
        "Deliverables:\n"
        "- Emergency RFC change_id for containment actions\n"
        "- Containment actions executed with timestamps\n"
        "- Systems isolated; forensic evidence preserved with chain-of-custody\n"
        "- IOCs identified; eradication recommendations\n"
        "- Risk assessment for remaining uncontained systems"
    ),
    agent=agents[4],
    expected_output=(
        "Containment & Emergency RFC report: (1) change_id of submitted emergency RFC, "
        "(2) attack scope and IOCs, (3) systems isolated with timestamps, (4) forensic evidence preserved, "
        "(5) lateral movement assessment, (6) eradication recommendations, (7) detection indicators."
    ),
    context=[task_classify],
)

task_recover = Task(
    description=(
        "DR EXECUTION + EMERGENCY RFC FOR FAILOVER CHANGES (ITIL 4 Restore)\n\n"
        "Execute recovery using the prioritization from BIA:\n"
        "1. Call submit_rfc with category='emergency' to file an RFC for your failover/recovery changes. "
        "Include linked_incident_id from the classification task and a backout_plan describing how "
        "you would revert (e.g., DNS rollback). Capture the change_id.\n"
        "2. For each prioritized service, call check_service_health and query_cmdb, then failover_service\n"
        "3. Call execute_runbook for DNS_FAILOVER and CREDENTIAL_ROTATION as needed\n"
        "4. After successful failover, call execute_change with the change_id from step 1 to record the "
        "implementation against the CMDB. (CAB approval will be expedited in subsequent tasks.)\n"
        "5. Call log_lesson to capture interventions for the PIR\n\n"
        "Deliverables:\n"
        "- Emergency RFC change_id for failover changes\n"
        "- Per-service recovery status and RTO/RPO outcomes\n"
        "- Validation results post-failover\n"
        "- Manual interventions performed"
    ),
    agent=agents[2],
    expected_output=(
        "Recovery + Emergency RFC report: change_id, timeline of failover actions, per-service status, "
        "RTO achievement, RPO data loss assessment, post-failover validation, manual interventions, lessons."
    ),
    context=[task_classify, task_bia],
)

task_emergency_tech_review = Task(
    description=(
        "EMERGENCY-CAB TECHNICAL REVIEW\n\n"
        "Two emergency RFCs were submitted during this incident — one by SecOps (containment) and one "
        "by Recovery (failover). Even under emergency procedures, the CAB performs an abbreviated "
        "technical review to validate that the changes that were just executed (or are about to "
        "execute) had a tested backout plan and matched the affected CIs.\n\n"
        "For EACH emergency change_id mentioned in the prior task outputs:\n"
        "1. Call query_cmdb to verify the affected_cis listed match what was actually touched\n"
        "2. Call query_kedb to surface known errors that should have been considered\n"
        "3. Call review_rfc_technical with decision='approve' or 'request_changes', citing specific "
        "findings (e.g., 'backout plan validated against KE-2025-018', 'affected_cis missing API-GW-PROD'). "
        "For genuine emergencies, approval is expected unless something is materially wrong.\n\n"
        "Deliverables: technical review record per change_id with decision, findings, and KEDB references."
    ),
    agent=agents[6],
    expected_output=(
        "Emergency-CAB technical review log: per-change_id decision (approve/request_changes/reject) with "
        "findings, KEDB matches, and backout plan validation."
    ),
    context=[task_contain, task_recover],
)

task_emergency_risk_review = Task(
    description=(
        "EMERGENCY-CAB RISK & COMPLIANCE REVIEW\n\n"
        "Score risk and check regulatory exposure for the emergency RFCs reviewed in the prior task. "
        "For EACH emergency change_id:\n"
        "1. Call review_rfc_risk — this computes risk_score (probability × impact), queries the KEDB, "
        "checks the change calendar, and identifies required approvers. Provide compliance_concerns "
        "(comma-separated) for any frameworks (PCI-DSS, SOX, GDPR) impacted.\n"
        "2. Call check_compliance_status to capture regulatory notification deadlines\n"
        "3. Note: emergency changes are permitted to override most freeze windows (allows_emergency=True)\n\n"
        "Deliverables: risk review per change_id with risk_level, score, KEDB matches, and approver chain."
    ),
    agent=agents[7],
    expected_output=(
        "Emergency-CAB risk review log: per-change_id risk_level, risk_score, probability/impact, "
        "KEDB matches, calendar/freeze conflicts (if any), required approvers, compliance concerns."
    ),
    context=[task_contain, task_recover, task_emergency_tech_review],
)

task_emergency_cab_decision = Task(
    description=(
        "EMERGENCY-CAB DECISION & PIR\n\n"
        "Convene the abbreviated emergency CAB and record decisions. For each emergency change_id:\n"
        "1. Call cab_decision with decision='approve' (or 'reject' if a reviewer flagged a fatal issue), "
        "voting_members='CAB Chair, Service Owner on-call, Risk & Compliance, Technical Reviewer', "
        "and a clear rationale tying back to the incident_id.\n"
        "2. After approval, conduct PIR via conduct_pir with objective_met=true if the change achieved "
        "the recovery objective, lessons_learned (comma-separated), and remediation_items in the "
        "format 'description|owner|YYYY-MM-DD|priority'. If the failover surfaced a recurring DR "
        "weakness, set promote_to_standard=false (emergency procedures don't promote to standard) but "
        "still record the lesson.\n\n"
        "Deliverables: CAB decision and PIR per emergency change_id."
    ),
    agent=agents[8],
    expected_output=(
        "Emergency CAB decision log + PIR: per-change_id approval/rejection with voting members, conditions, "
        "and a complete PIR with objective met status, lessons learned, and remediation items."
    ),
    context=[task_contain, task_recover, task_emergency_tech_review, task_emergency_risk_review],
)

task_comms = Task(
    description=(
        "STAKEHOLDER COMMUNICATION & REGULATORY REPORTING (FFIEC BCM Handbook)\n\n"
        "Manage communications across all stakeholder groups with compliance focus:\n"
        "1. Call coordinate_war_room to set up and manage incident war room\n"
        "2. Call check_compliance_status for regulatory notification deadlines\n"
        "3. Send notifications via send_notification for each audience: customers (empathetic), "
        "executives (financial/risk), regulators (compliance), technical teams, third-party vendors\n"
        "4. Track timeline for regulatory deadlines (GDPR 72h, etc.)\n\n"
        "Deliverables: war room log, communication timeline, regulatory verification, executive briefing."
    ),
    agent=agents[3],
    expected_output=(
        "Communications & Regulatory Reporting Summary: war room log, complete notification timeline, "
        "regulatory verification, customer communications, executive briefing, vendor coordination."
    ),
    context=[task_classify, task_bia, task_recover, task_emergency_cab_decision],
)


# ============================================================================
# CHANGE-MANAGEMENT TASKS (non-incident: standard, normal, failed)
# ============================================================================

task_change_submit = Task(
    description=(
        "SUBMIT REQUEST FOR CHANGE\n\n"
        "Change request: {event_description}\n\n"
        "As the Service Owner:\n"
        "1. Call query_cmdb to confirm the CIs you intend to touch and their current state\n"
        "2. Call query_kedb to surface any known errors on those CIs — cite the entries you find\n"
        "3. Call query_change_calendar with your proposed window and affected_cis to detect collisions "
        "with scheduled changes or freeze windows BEFORE submitting\n"
        "4. Call submit_rfc:\n"
        "   - For a standard, pre-approved change: category='standard' and provide standard_template_id\n"
        "     (e.g., STD-CERT-001 for cert rotation, STD-DNS-TTL-001 for TTL adjustment, "
        "     STD-SCALE-001 for autoscale changes)\n"
        "   - For a normal change: category='normal'; the CAB will review\n"
        "   - Include a tested backout_plan and test_evidence (URLs, ticket IDs)\n"
        "5. Capture the change_id; downstream tasks reference it.\n\n"
        "Deliverables: change_id, KEDB references checked, calendar conflicts (if any), and the "
        "submitted RFC's category and chosen window."
    ),
    agent=agents[5],
    expected_output=(
        "RFC submission record: change_id, category (standard|normal), affected_cis, planned window, "
        "KEDB references consulted, backout plan summary, calendar status."
    ),
)

task_change_tech_review = Task(
    description=(
        "TECHNICAL REVIEW (CAB)\n\n"
        "Review the RFC submitted in the prior task. Apply the four-check rule:\n"
        "1. Implementation plan complete and runnable?\n"
        "2. Backout plan tested? (Use query_kedb to see if related rollbacks have failed before.)\n"
        "3. Test evidence present and from the correct environment?\n"
        "4. affected_cis list matches what query_cmdb says will be touched?\n\n"
        "Call review_rfc_technical with decision='approve', 'reject', or 'request_changes' and "
        "specific findings. Use the change_id from the submission task."
    ),
    agent=agents[6],
    expected_output=(
        "Technical review: change_id, decision, four-check results, findings, KEDB references."
    ),
    context=[task_change_submit],
)

task_change_risk_review = Task(
    description=(
        "RISK & COMPLIANCE REVIEW (CAB)\n\n"
        "For the technically-reviewed RFC:\n"
        "1. Call review_rfc_risk to compute risk_score, identify KEDB matches, and detect calendar/"
        "freeze conflicts. Provide compliance_concerns based on the affected CIs (PCI-DSS, SOX, GDPR).\n"
        "2. Call check_compliance_status for any framework-specific notification or audit requirements.\n"
        "3. If the calendar shows a freeze-window conflict and category is not emergency, the review "
        "MUST reject — recommend rescheduling outside the freeze."
    ),
    agent=agents[7],
    expected_output=(
        "Risk review: change_id, risk_level (low/medium/high/critical), risk_score, probability/impact, "
        "KEDB matches, calendar/freeze conflicts, required approver chain, compliance concerns."
    ),
    context=[task_change_submit, task_change_tech_review],
)

task_change_cab_decision = Task(
    description=(
        "CAB DECISION & SCHEDULING\n\n"
        "Convene the CAB. For the RFC:\n"
        "1. Call cab_decision with decision='approve' or 'reject', voting_members reflecting the risk "
        "tier (LOW: Service Owner; MEDIUM: + Technical Reviewer; HIGH: + Risk & Compliance + CAB Chair; "
        "CRITICAL: + CISO + CIO), conditions (any limits attached to approval), and a rationale.\n"
        "2. If approved, call schedule_change with the agreed planned_start and planned_end. If the "
        "calendar rejects the window (conflict or freeze), pick a different window. Do NOT skip this step."
    ),
    agent=agents[8],
    expected_output=(
        "CAB decision: change_id, decision, voting members, conditions, rationale; "
        "if approved, scheduled window confirmation."
    ),
    context=[task_change_submit, task_change_tech_review, task_change_risk_review],
)

task_change_implement = Task(
    description=(
        "IMPLEMENT THE APPROVED CHANGE\n\n"
        "Execute the approved and scheduled change:\n"
        "1. Call execute_change with the change_id and your role as implementer. Provide cmdb_updates "
        "as a comma-separated list in the format 'CI:key=value' "
        "(e.g., 'AUTH-SVC-CERT:current_version=expires 2027-06-15').\n"
        "2. If the post-checks indicate failure (or if the scenario brief says 'force_backout'), "
        "set force_backout=true to trigger the backout plan and demonstrate the rollback path.\n"
        "3. Confirm the implementation outcome (success / partial / failed / backed_out)."
    ),
    agent=agents[5],
    expected_output=(
        "Implementation result: change_id, outcome, pre/post-check results, CMDB updates applied, "
        "and (if applicable) backout execution log."
    ),
    context=[task_change_submit, task_change_cab_decision],
)

task_change_pir = Task(
    description=(
        "POST-IMPLEMENTATION REVIEW (CAB)\n\n"
        "Conduct the PIR for the implemented change:\n"
        "1. Call conduct_pir with objective_met (was the stated outcome achieved?), "
        "unexpected_side_effects (comma-separated), lessons_learned (comma-separated), and "
        "remediation_items in the format 'description|owner|YYYY-MM-DD|priority'.\n"
        "2. If the change was routine, low-risk, and ran cleanly, set promote_to_standard=true and "
        "provide promote_rationale; then call promote_to_standard to register a new standard template "
        "for future identical changes.\n"
        "3. If the change was backed out, the PIR must record what was learned and add a remediation "
        "item to address the root cause."
    ),
    agent=agents[8],
    expected_output=(
        "PIR record: change_id, objective_met, unexpected_side_effects, backout_was_needed, "
        "lessons_learned, remediation_items with owners and due dates, promote_to_standard verdict, "
        "and (if promoted) the new template_id."
    ),
    context=[task_change_submit, task_change_cab_decision, task_change_implement],
)


# Sequence helpers used by bcm_crew.py
INCIDENT_TASKS = [
    task_classify,
    task_bia,
    task_contain,
    task_recover,
    task_emergency_tech_review,
    task_emergency_risk_review,
    task_emergency_cab_decision,
    task_comms,
]

NORMAL_CHANGE_TASKS = [
    task_change_submit,
    task_change_tech_review,
    task_change_risk_review,
    task_change_cab_decision,
    task_change_implement,
    task_change_pir,
]

# Standard changes are pre-approved by template, so the formal review tasks are skipped.
# The submission auto-promotes the change to APPROVED inside submit_rfc, so the
# implementer can execute directly.
STANDARD_CHANGE_TASKS = [
    task_change_submit,
    task_change_implement,
    task_change_pir,
]

# Failed-change scenario uses the same task graph as a normal change; the scenario
# brief instructs the implementer to set force_backout=true.
FAILED_CHANGE_TASKS = NORMAL_CHANGE_TASKS


# Backwards-compat exports — old call sites used task1..task6.
task1 = task_classify
task2 = task_bia
task3 = task_contain
task4 = task_recover
task5 = task_emergency_cab_decision
task6 = task_comms
