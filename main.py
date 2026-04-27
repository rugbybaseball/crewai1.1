from src.bcm_crew import create_bcm_crew
from simulation_engine import SimulationEngine


# INSTRUCTOR: Change this before each live round
EVENT_SCENARIO = "ransomware"  # Options: ransomware, cloud_outage_ddos, data_breach, insider_threat, supply_chain, cascading_failure

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
    )
}

event_description = EVENTS[EVENT_SCENARIO]

print(f"🚨 INSTRUCTOR TRIGGERED EVENT: {EVENT_SCENARIO.upper()}")
print(f"Description: {event_description}\n")
print("="*80)
print("Activating FinServe Business Continuity Management Crew...")
print("="*80)
print()

crew = create_bcm_crew()
result = crew.kickoff(inputs={"event_description": event_description})

print("\n" + "="*80)
print("FINAL RECOVERY PLAN FROM STUDENT AGENTS:")
print(result)
print("="*80)

# Auto-grade using multi-dimensional scoring engine
engine = SimulationEngine()
score = engine.evaluate(result, EVENT_SCENARIO)
print(f"\n🎯 OVERALL KPI SCORE: {score['overall_kpi_score']}%")
print(f"📊 Detailed Scoring:")
for key, value in score.items():
    if key != 'overall_kpi_score':
        print(f"   {key}: {value}")