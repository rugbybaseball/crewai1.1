import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from src.bcm_crew import create_bcm_crew, category_for_scenario
from simulation_engine import SimulationEngine


# INSTRUCTOR: Change this before each live round
EVENT_SCENARIO = "ransomware"
# Incident-driven (full incident response + emergency CAB):
#   ransomware, cloud_outage_ddos, data_breach, insider_threat, supply_chain, cascading_failure
# Change-management (no incident; CAB lifecycle on the active document):
#   standard_cert_rotation, normal_db_upgrade, failed_change_rollback


EVENTS = {
    "ransomware": (
        "A ransomware attack has encrypted the primary data center using LockBit variant. "
        "Mobile banking and online transfer services are down. Database replication is blocked. "
        "No data exfiltration confirmed yet but ransom note appears on admin console. "
        "Incident detected at 14:32 UTC. Attack signature matches known LockBit C2 infrastructure."
    ),
    "cloud_outage_ddos": (
        "AWS us-east-1 region is experiencing a major infrastructure outage compounded by simultaneous "
        "multi-vector DDoS attack (volumetric + protocol + application layer). All FinServe services in that region degraded. "
        "Payment Processing at 15% capacity. Database replication lag >5 minutes. Third-party vendors reporting similar issues."
    ),
    "data_breach": (
        "Security team detected unauthorized access to customer database containing 2.3M records (PII, email, phone, SSN, credit card). "
        "Attack vector: compromised service account with excessive permissions used for 6 hours. "
        "Anomalous egress traffic detected: 47GB of data exported to attacker-controlled cloud storage. "
        "Exfiltration confirmed via DNS query logs and network TAP data. "
        "Data includes PCI-DSS regulated payment card data and GDPR-protected personal data."
    ),
    "insider_threat": (
        "Compliance monitoring detected privileged database administrator (John Martinez, 12 years tenure) "
        "exporting large volumes of customer financial data and transaction history to personal AWS S3 bucket. "
        "Activity spans 3 weeks: 890GB of data extracted in 145 separate operations. "
        "User attempted to cover tracks by deleting CloudTrail logs (unsuccessful—replicated to separate account). "
        "Motive suspected to be contract with competitor bank. Admin has been suspended pending investigation."
    ),
    "supply_chain": (
        "PayBridge Inc, our critical third-party payment processor (handles 60% of all card transactions), "
        "disclosed a compromise of their API gateway. Attackers gained access via unpatched RCE vulnerability (CVE-2024-1234). "
        "FinServe transactions processed through PayBridge in the last 48 hours (1.2M transactions, $340M volume) may have been intercepted. "
        "Card data exposure possible. PayBridge is offline—no ETA for recovery. Incident impacts all downstream customers."
    ),
    "cascading_failure": (
        "Critical database migration during planned maintenance window at 02:00 UTC failed catastrophically. "
        "Automatic rollback trigger failed due to concurrent backup process holding locks. "
        "Transaction ledger database now has corrupted data propagating downstream to: "
        "Reconciliation System (corrupted 89K records), Fraud Detection (stale/incorrect data), Regulatory Reporting (invalid balances). "
        "Corruption discovered during normal reconciliation process at 06:15 UTC—already impacting 4 hours of transaction history. "
        "Point-in-time recovery available from 23:30 UTC backup (3.5 hours of data loss)."
    ),

    # ------------------------------------------------------------------
    # Change-management scenarios (no incident).
    # The crew runs the CAB lifecycle: submit -> [reviews] -> decision -> implement -> PIR.
    # ------------------------------------------------------------------

    "standard_cert_rotation": (
        "Pre-approved standard change: rotate the TLS certificate on AUTH-SVC-CERT before its "
        "2026-06-15 expiry. Use standard template STD-CERT-001 (used 47 times prior, all successful). "
        "Affected CI: AUTH-SVC-CERT (PKI Team). The change is pre-approved by the template, so the "
        "RFC auto-promotes to APPROVED on submission and proceeds straight to implementation. "
        "After the cert is rotated, conduct PIR and confirm whether the template should be retained "
        "as-is or updated."
    ),
    "normal_db_upgrade": (
        "Normal change request: upgrade DB-PRIMARY-01 from PostgreSQL 14.8 to 15.5 (minor version "
        "upgrade following vendor security advisory). Affected CI: DB-PRIMARY-01 (DBA Team). "
        "Backout plan: snapshot before upgrade; pg_upgrade has been validated in staging; full restore "
        "from snapshot if post-checks fail. Test evidence: ticket QA-2026-441 (staging upgrade passed "
        "all 1,200 regression tests). Note KEDB entry KE-2025-031 about concurrent backup lock "
        "contention — schedule outside the 02:00 UTC backup window. Avoid any active freeze window "
        "(month-end close runs 2026-04-28 to 2026-04-30). Propose a window of 2026-05-04 03:00-05:00 "
        "UTC and let the calendar/CAB confirm."
    ),
    "failed_change_rollback": (
        "Normal change request: deploy v3.3.0 of API-GW-PROD (API gateway). Affected CI: API-GW-PROD "
        "(Platform Team). Backout plan: revert to v3.2.1 via blue/green swap. Test evidence: "
        "ticket QA-2026-502. Schedule for 2026-05-06 04:00-06:00 UTC. "
        "IMPORTANT FOR THE IMPLEMENTER: this scenario simulates a failed change — when calling "
        "execute_change, set force_backout=true. The PIR must document the rollback, capture "
        "lessons learned, and add a remediation item with owner and due date so the failure feeds "
        "back into the KEDB."
    ),
}


event_description = EVENTS[EVENT_SCENARIO]
category = category_for_scenario(EVENT_SCENARIO)

print(f"🚨 INSTRUCTOR TRIGGERED EVENT: {EVENT_SCENARIO.upper()} (category: {category})")
print(f"Description: {event_description}\n")
print("=" * 80)
print("Activating FinServe Business Continuity Management Crew...")
print("=" * 80)
print()

crew = create_bcm_crew(EVENT_SCENARIO)
result = crew.kickoff(inputs={"event_description": event_description})

print("\n" + "=" * 80)
print("FINAL OUTPUT:")
print(result)
print("=" * 80)

engine = SimulationEngine()
score = engine.evaluate(result, EVENT_SCENARIO)
print(f"\n🎯 OVERALL KPI SCORE: {score['overall_kpi_score']}%")
print(f"📊 Detailed Scoring:")
for key, value in score.items():
    if key != "overall_kpi_score":
        print(f"   {key}: {value}")
