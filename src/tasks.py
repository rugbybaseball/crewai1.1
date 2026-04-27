from crewai import Task
from src.agents import create_agents

agents = create_agents()

# Task 1: Incident Detection & Classification (NIST CSF & ITIL 4)
task1 = Task(
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
    )
)

# Task 2: Business Impact Assessment (BIA with financial modeling)
task2 = Task(
    description=(
        "BUSINESS IMPACT ANALYSIS (ISO 22301 & FFIEC Guidelines)\n\n"
        "Based on incident from Task 1, conduct comprehensive BIA:\n"
        "1. For each affected service, call calculate_impact to model financial exposure including:\n"
        "   - Direct revenue loss with time-based degradation curves\n"
        "   - SLA penalty exposure\n"
        "   - Regulatory fine risk (PCI-DSS, SOX, GDPR, FFIEC)\n"
        "   - Reputational damage scoring\n"
        "   - Customer churn probability\n"
        "   - Cascading impacts on dependent services\n"
        "2. Call check_compliance_status to identify impacted regulatory controls and notification deadlines\n"
        "3. Call assess_vendor_impact for third-party service dependencies\n\n"
        "Deliverables:\n"
        "- Prioritized recovery list (RTO-based): which services restore in what order\n"
        "- Financial impact projection: cumulative loss per hour\n"
        "- Regulatory exposure summary with specific deadlines (GDPR 72h, PCI breach notification, etc.)\n"
        "- Vendor impact assessment and alternative vendor lead times\n"
        "- Recovery priority matrix (Impact vs Urgency)\n"
        "- Executive summary of financial and regulatory risk"
    ),
    agent=agents[1],
    expected_output=(
        "Business Impact Analysis report with: (1) Prioritized service recovery list ordered by RTO, "
        "(2) Financial impact projections with time horizons, (3) Regulatory compliance impact with specific articles/controls, "
        "(4) SLA penalty exposure quantified, (5) Vendor impact assessment, (6) Customer churn probability, "
        "(7) Executive-level financial summary, (8) Recovery priority recommendations"
    ),
    context=[task1]
)

# Task 3: Security Containment & Forensics (NIST CSF Respond & Recover)
task3 = Task(
    description=(
        "SECURITY CONTAINMENT & FORENSIC PRESERVATION (NIST CSF Respond)\n\n"
        "Execute immediate containment to prevent lateral movement and preserve forensic evidence:\n"
        "1. Call analyze_security_event to identify attack scope, IOCs, and lateral movement risk\n"
        "2. Call query_cmdb to map affected systems and adjacent risks\n"
        "3. Execute ISOLATE_NETWORK and FORENSIC_SNAPSHOT runbooks via execute_runbook:\n"
        "   - Network isolation to prevent data exfiltration\n"
        "   - Forensic snapshot for evidence preservation\n"
        "   - Chain-of-custody documentation\n"
        "4. Monitor check_service_health for signs of lateral movement\n\n"
        "Deliverables:\n"
        "- Containment actions executed with timestamps\n"
        "- Systems isolated and taken off-network\n"
        "- Forensic evidence preserved with chain-of-custody\n"
        "- IOCs identified and indicators for detection added to SIEM\n"
        "- Eradication recommendations (credential rotation, patch requirements)\n"
        "- Risk assessment for remaining uncontained systems"
    ),
    agent=agents[4],
    expected_output=(
        "Containment and Forensics report: (1) Attack scope and IOCs identified, (2) Systems isolated with timestamps, "
        "(3) Forensic evidence preserved and documented, (4) Lateral movement assessment, (5) Eradication recommendations, "
        "(6) Remaining risk assessment, (7) Detection indicators for SIEM/monitoring"
    ),
    context=[task1]
)

# Task 4: Recovery Execution & Validation (ITIL 4 Recovery & Restore)
task4 = Task(
    description=(
        "DISASTER RECOVERY EXECUTION & VALIDATION (ITIL 4 Restore)\n\n"
        "Execute recovery plan based on BIA prioritization from Task 2:\n"
        "1. For each service in prioritized order from Task 2, execute failover:\n"
        "   - Call check_service_health to assess DR site readiness\n"
        "   - Call query_cmdb to understand service dependencies and recovery sequence\n"
        "   - Call failover_service to trigger failover with validation\n"
        "2. Execute DNS failover and traffic rerouting via execute_runbook (DNS_FAILOVER)\n"
        "3. Validate post-failover health: connectivity, throughput, error rates, data integrity\n"
        "4. Monitor for cascading failures in dependent services\n"
        "5. Call log_lesson to document recovery timeline, issues encountered, and manual interventions\n\n"
        "Deliverables:\n"
        "- Recovery execution timeline with T+0 baseline\n"
        "- Each service failover status: success, partial, failed, data loss\n"
        "- Pre/post failover health metrics comparison\n"
        "- Data integrity validation results\n"
        "- Manual interventions required and completed\n"
        "- RTO achievement vs planned targets\n"
        "- Lessons learned for post-incident review"
    ),
    agent=agents[2],
    expected_output=(
        "Recovery Execution Report: (1) Timeline of failover actions with T+ timestamps, (2) Per-service recovery status, "
        "(3) RTO achievement vs planned targets, (4) RPO data loss assessment, (5) Post-failover validation results, "
        "(6) Manual interventions performed, (7) Minimum viable operation achieved confirmation, (8) Lessons learned and recommendations"
    ),
    context=[task1, task2]
)

# Task 5: Emergency Change Management (ITIL 4 Change Control)
task5 = Task(
    description=(
        "EMERGENCY CHANGE MANAGEMENT (ITIL 4 Change Control)\n\n"
        "Manage emergency changes and recovery procedures with proper control and documentation:\n"
        "1. Query CMDB via query_cmdb to understand all affected systems and change dependencies\n"
        "2. Review compliance requirements for emergency changes via check_compliance_status\n"
        "3. Execute recovery runbooks with change tracking: credential rotation, patch deployment, configuration updates\n"
        "4. Document each change: what changed, why, expected impact, rollback procedure\n"
        "5. Call log_lesson to record change management decisions and any control gaps\n\n"
        "Deliverables:\n"
        "- Emergency Change Advisory Board (CAB) approval summary\n"
        "- Change log documenting all emergency changes with:\n"
        "  * Change ID, description, impact assessment, rollback plan\n"
        "  * Pre/post-change validation results\n"
        "  * Compliance assessment (did emergency procedures meet control requirements?)\n"
        "- Risk assessment for each change\n"
        "- Audit trail for compliance and forensics\n"
        "- Recommendations for process improvements to enable faster emergency changes"
    ),
    agent=agents[5],
    expected_output=(
        "Emergency Change Management Report: (1) List of all emergency changes approved with CAB summary, (2) Change details including "
        "impact assessment and rollback procedures, (3) Compliance verification for emergency change process, (4) Pre/post change validation, "
        "(5) Risk assessments, (6) Complete audit trail, (7) Process improvement recommendations"
    ),
    context=[task1, task3, task4]
)

# Task 6: Stakeholder Communication & Regulatory Reporting
task6 = Task(
    description=(
        "STAKEHOLDER COMMUNICATION & REGULATORY REPORTING (FFIEC BCM Handbook)\n\n"
        "Manage communications across all stakeholder groups with compliance focus:\n"
        "1. Call coordinate_war_room to set up and manage incident war room for internal coordination\n"
        "2. Call check_compliance_status to identify regulatory notification requirements and deadlines\n"
        "3. Draft and send notifications via send_notification for each audience group:\n"
        "   - CUSTOMERS: Simple, empathetic, no jargon, workaround instructions, ETA for resolution\n"
        "   - EXECUTIVES/BOARD: Financial impact, risk posture, decision points, status updates\n"
        "   - REGULATORS: Compliance-focused, specific regulations cited (PCI-DSS, SOX, GDPR), formal notification\n"
        "   - TECHNICAL TEAMS: Detailed technical context, runbooks, escalation contacts, war room bridge\n"
        "   - THIRD-PARTY VENDORS: SLA references, contractual obligations, coordination requirements\n"
        "4. Track communication timeline to ensure regulatory deadlines are met (GDPR 72h, etc.)\n"
        "5. Ensure consistent messaging across all channels\n\n"
        "Deliverables:\n"
        "- War room log with participants, decisions, action items, escalation triggers\n"
        "- Communication timeline showing all messages sent to all audiences\n"
        "- Regulatory notification status: deadlines identified and compliance verified\n"
        "- Customer communication tracking: method (email/SMS/status page), delivery confirmation\n"
        "- Executive briefing documenting financial/regulatory exposure and recovery status\n"
        "- Post-communication summary with lessons for future incident messaging"
    ),
    agent=agents[3],
    expected_output=(
        "Communications & Regulatory Reporting Summary: (1) War room coordination log with decisions and action items, "
        "(2) Complete timeline of all notifications sent with audience, channel, and delivery status, "
        "(3) Regulatory notification verification with specific deadlines (GDPR 72h, PCI breach notification, etc.), "
        "(4) Customer communication summary with delivery metrics, (5) Executive briefing with financial/regulatory summary, "
        "(6) Vendor communication and SLA impact acknowledgment, (7) Communications lessons learned"
    ),
    context=[task1, task2, task4]
)
