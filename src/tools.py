from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
import hashlib
import json

# ============================================================================
# DATA MODELS FOR STRUCTURED OUTPUTS
# ============================================================================

class SecurityEventAnalysis(BaseModel):
    """NIST CSF-aligned security event classification"""
    severity: str = Field(description="P1-P5 priority level")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID")
    attack_vector: str = Field(description="Network, Physical, Adjacent, Local")
    iocs: List[str] = Field(description="Indicators of compromise")
    affected_components: List[str] = Field(description="Infrastructure components affected")
    blast_radius_pct: int = Field(description="Estimated % of services impacted")
    lateral_movement_suspected: bool = Field(description="Horizontal movement detected")
    containment_actions: List[str] = Field(description="Recommended containment steps")
    cve_references: List[str] = Field(description="Related CVE IDs if applicable")


class ServiceImpactAnalysis(BaseModel):
    """Financial and operational impact metrics"""
    service_name: str
    customers_impacted: int
    hourly_revenue_loss: float
    cumulative_financial_impact: float
    sla_penalty_exposure: float
    regulatory_fine_risk: float
    regulatory_body: str
    reputational_damage_score: int
    customer_churn_probability_pct: float
    time_of_day_multiplier: float
    cascading_impact_on_dependencies: Dict[str, float]


class FailoverResult(BaseModel):
    """Detailed failover execution results"""
    service_name: str
    status: str  # "success", "partial", "failed", "data_loss"
    pre_failover_health: Dict[str, Any]
    replication_lag_seconds: int
    failover_duration_seconds: int
    execution_steps: List[Dict[str, str]]
    validation_results: Dict[str, bool]
    manual_intervention_required: List[str]
    data_loss_records: int


class IncidentRecord(BaseModel):
    """ITIL 4 incident management structure"""
    incident_id: str
    priority: str  # P1-P4
    impact: str  # High/Medium/Low
    urgency: str  # High/Medium/Low
    category: str
    subcategory: str
    affected_cis: List[str]
    assignment_group: str
    escalation_path: List[str]
    sla_clock_start: str
    bcm_plan_status: str
    emergency_change_required: bool


# ============================================================================
# THREAT INTELLIGENCE LOOKUP TABLE
# ============================================================================

THREAT_INTELLIGENCE = {
    "ransomware": {
        "tactic": "T1486: Impact",
        "technique": "T1486",
        "severity": "P1",
        "vector": "Network",
        "iocs": ["*.exe", "ransom note files", "encrypted file extensions"],
        "cves": ["CVE-2024-1234", "CVE-2024-5678"]
    },
    "ddos": {
        "tactic": "T1498: Denial of Service",
        "technique": "T1498",
        "severity": "P1",
        "vector": "Network",
        "iocs": ["traffic spike >1000%", "source IP flooding"],
        "cves": ["CVE-2024-9999"]
    },
    "data breach": {
        "tactic": "T1005: Data from Local System",
        "technique": "T1005",
        "severity": "P1",
        "vector": "Network",
        "iocs": ["exfiltration traffic", "unusual egress patterns"],
        "cves": ["CVE-2024-3333"]
    },
    "insider threat": {
        "tactic": "T1020: Automated Exfiltration",
        "technique": "T1020",
        "severity": "P1",
        "vector": "Adjacent",
        "iocs": ["privileged user activity", "cloud upload unusual volume"],
        "cves": []
    },
    "supply chain": {
        "tactic": "T1195: Supply Chain Compromise",
        "technique": "T1195",
        "severity": "P1",
        "vector": "Network",
        "iocs": ["vendor API compromise", "malicious updates"],
        "cves": ["CVE-2024-7777"]
    },
    "misconfiguration": {
        "tactic": "T1526: Exposure of Cloud Service to Internet",
        "technique": "T1526",
        "severity": "P2",
        "vector": "Network",
        "iocs": ["exposed S3 bucket", "public database"],
        "cves": []
    }
}

# SERVICE CATALOG WITH DEPENDENCIES
SERVICE_CATALOG = {
    "Mobile Banking": {
        "tier": 1,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 6,
        "owner": "Banking Services Team",
        "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-15",
        "dr_test_result": "PASSED",
        "customers": 1_200_000,
        "hourly_revenue": 2_400_000,
        "dependencies": [],
        "compliance": ["PCI-DSS 3.4", "SOX 302", "GDPR 5.1"]
    },
    "Fraud Detection": {
        "tier": 1,
        "rto_hours": 2,
        "rpo_minutes": 5,
        "mtpd_hours": 3,
        "owner": "Risk Management Team",
        "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-10",
        "dr_test_result": "PASSED",
        "customers": 800_000,
        "hourly_revenue": 1_800_000,
        "dependencies": ["Payment Processing"],
        "compliance": ["PCI-DSS 6.5.10", "FFIEC BCM"]
    },
    "Online Transfers": {
        "tier": 1,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 6,
        "owner": "Core Banking Team",
        "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-12",
        "dr_test_result": "PASSED",
        "customers": 500_000,
        "hourly_revenue": 1_100_000,
        "dependencies": ["Mobile Banking", "Payment Processing"],
        "compliance": ["PCI-DSS 3.4", "SOX 302"]
    },
    "Payment Processing": {
        "tier": 1,
        "rto_hours": 1,
        "rpo_minutes": 1,
        "mtpd_hours": 2,
        "owner": "Payments Team",
        "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-18",
        "dr_test_result": "PASSED",
        "customers": 2_000_000,
        "hourly_revenue": 3_500_000,
        "dependencies": [],
        "compliance": ["PCI-DSS 1.0", "PCI-DSS 3.2", "NACHA Rules"]
    },
    "Loan Management": {
        "tier": 2,
        "rto_hours": 8,
        "rpo_minutes": 30,
        "mtpd_hours": 12,
        "owner": "Lending Operations",
        "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-28",
        "dr_test_result": "PASSED",
        "customers": 400_000,
        "hourly_revenue": 500_000,
        "dependencies": ["Mobile Banking"],
        "compliance": ["SOX 302", "FDIC Requirements"]
    },
    "Investment Services": {
        "tier": 2,
        "rto_hours": 8,
        "rpo_minutes": 60,
        "mtpd_hours": 24,
        "owner": "Wealth Management",
        "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-20",
        "dr_test_result": "FAILED - Manual Recovery Needed",
        "customers": 200_000,
        "hourly_revenue": 300_000,
        "dependencies": ["Payment Processing"],
        "compliance": ["SEC 17a-3", "SOX 302"]
    },
    "Customer Portal": {
        "tier": 2,
        "rto_hours": 12,
        "rpo_minutes": 120,
        "mtpd_hours": 24,
        "owner": "Digital Services",
        "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-03-05",
        "dr_test_result": "PASSED",
        "customers": 1_500_000,
        "hourly_revenue": 0,
        "dependencies": ["Mobile Banking", "Online Transfers"],
        "compliance": ["GDPR 5.1", "WCAG 2.1"]
    },
    "Data Warehouse": {
        "tier": 3,
        "rto_hours": 24,
        "rpo_minutes": 360,
        "mtpd_hours": 48,
        "owner": "Analytics Team",
        "dr_strategy": "Cold Standby",
        "last_dr_test": "2026-01-30",
        "dr_test_result": "PASSED",
        "customers": 0,
        "hourly_revenue": 0,
        "dependencies": [],
        "compliance": ["GDPR 5.1", "Data Residency"]
    },
    "Compliance Reporting": {
        "tier": 3,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 8,
        "owner": "Compliance Team",
        "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-14",
        "dr_test_result": "PASSED",
        "customers": 0,
        "hourly_revenue": 0,
        "dependencies": ["Data Warehouse"],
        "compliance": ["SOX 302", "FDIC 365.2"]
    }
}

# RUNBOOK CATALOG
RUNBOOKS = {
    "ISOLATE_NETWORK": {
        "name": "Network Isolation Protocol",
        "steps": [
            "Identify affected VLAN/subnet",
            "Enable port security on switches",
            "Block ingress/egress routes",
            "Snapshot current state for forensics",
            "Notify network security team"
        ]
    },
    "FORENSIC_SNAPSHOT": {
        "name": "Forensic Evidence Preservation",
        "steps": [
            "Capture memory image of affected systems",
            "Lock affected disks from modification",
            "Generate file system checksums",
            "Export logs to secure repository",
            "Create chain-of-custody documentation"
        ]
    },
    "CREDENTIAL_ROTATION": {
        "name": "Emergency Credential Rotation",
        "steps": [
            "Identify all affected service accounts",
            "Generate new credentials",
            "Rotate in non-production first",
            "Update application configs",
            "Audit successful authentication with new creds"
        ]
    },
    "DNS_FAILOVER": {
        "name": "DNS and Traffic Failover",
        "steps": [
            "Update DNS TTL to 60 seconds",
            "Verify secondary datacenter readiness",
            "Redirect traffic via load balancer",
            "Monitor for connection timeouts",
            "Confirm secondary receiving >95% traffic"
        ]
    }
}

# ============================================================================
# ENHANCED TOOLS
# ============================================================================

class AnalyzeSecurityEventTool(BaseTool):
    """Enhanced to support 6+ event types with MITRE ATT&CK mapping and threat intel"""
    name: str = "analyze_security_event"
    description: str = (
        "Analyzes security/infrastructure events with MITRE ATT&CK mapping, "
        "IOC extraction, and blast radius estimation using threat intelligence lookup."
    )

    def _run(self, event_description: str) -> str:
        event_lower = event_description.lower()

        # Identify event type from keywords
        event_type = None
        for threat_type in THREAT_INTELLIGENCE.keys():
            if threat_type.replace(" ", "") in event_lower.replace(" ", ""):
                event_type = threat_type
                break

        if not event_type:
            # Fallback detection based on keywords
            if any(x in event_lower for x in ["encrypt", "ransomware", "locked"]):
                event_type = "ransomware"
            elif any(x in event_lower for x in ["ddos", "flood", "outage"]):
                event_type = "ddos"
            elif any(x in event_lower for x in ["breach", "exfiltrate", "access"]):
                event_type = "data breach"
            elif any(x in event_lower for x in ["insider", "unauthorized", "privileged"]):
                event_type = "insider threat"
            elif any(x in event_lower for x in ["vendor", "supply chain", "third-party"]):
                event_type = "supply chain"
            elif any(x in event_lower for x in ["misconfigur", "exposed", "public"]):
                event_type = "misconfiguration"
            else:
                event_type = "ddos"  # default fallback

        threat_data = THREAT_INTELLIGENCE.get(event_type, THREAT_INTELLIGENCE["ddos"])

        # Determine blast radius based on event type
        blast_radius_map = {
            "ransomware": 85,
            "ddos": 100,
            "data breach": 40,
            "insider threat": 30,
            "supply chain": 65,
            "misconfiguration": 25
        }

        # Determine affected components
        components_map = {
            "ransomware": ["Primary Data Center", "Storage Layer", "Backup Systems"],
            "ddos": ["Load Balancers", "CDN", "Network Egress"],
            "data breach": ["Database Tier", "API Gateway", "Data Export Paths"],
            "insider threat": ["Database Access Logs", "Cloud Storage", "Backup Repositories"],
            "supply chain": ["Third-party API Gateway", "Integration Points"],
            "misconfiguration": ["Cloud Storage", "Database Instances", "Security Groups"]
        }

        analysis = SecurityEventAnalysis(
            severity=threat_data["severity"],
            mitre_tactic=threat_data["tactic"],
            mitre_technique=threat_data["technique"],
            attack_vector=threat_data["vector"],
            iocs=threat_data["iocs"][:3],
            affected_components=components_map.get(event_type, ["Unknown"]),
            blast_radius_pct=blast_radius_map.get(event_type, 50),
            lateral_movement_suspected=event_type in ["ransomware", "insider threat", "data breach"],
            containment_actions=[
                "Isolate affected systems from network",
                "Preserve forensic evidence immediately",
                "Revoke all credentials for affected accounts",
                "Enable enhanced monitoring on adjacent systems"
            ],
            cve_references=threat_data.get("cves", [])
        )

        return json.dumps(analysis.model_dump(), indent=2)


class CreateIncidentRecordTool(BaseTool):
    """ITIL 4 incident record with priority matrix and escalation path"""
    name: str = "create_incident_record"
    description: str = (
        "Creates ITIL 4 compliant incident record with priority matrix, "
        "affected CIs, escalation path, and emergency change tracking."
    )

    def _run(self, severity: str, event_type: str, affected_services: str) -> str:
        # Priority matrix (Impact x Urgency)
        priority_map = {
            "P1": {"impact": "High", "urgency": "High"},
            "P2": {"impact": "High", "urgency": "Medium"},
            "P3": {"impact": "Medium", "urgency": "Medium"},
            "P4": {"impact": "Low", "urgency": "Low"}
        }

        priority = "P1" if severity in ["P1", "CATASTROPHIC"] else "P2" if severity in ["MAJOR", "P2"] else "P3"
        priority_data = priority_map[priority]

        # Generate incident ID (deterministic based on timestamp)
        now = datetime.utcnow()
        incident_hash = hashlib.md5(f"{event_type}{affected_services}{now}".encode()).hexdigest()[:5].upper()
        incident_id = f"INC-{now.strftime('%Y%m%d')}-{incident_hash}"

        # Escalation path based on priority
        escalation_map = {
            "P1": ["Service Owner", "ITSM Manager", "VP of IT", "CRO"],
            "P2": ["Service Owner", "Team Lead", "ITSM Manager"],
            "P3": ["Team Lead", "ITSM Coordinator"]
        }

        # Category/subcategory mapping
        category_map = {
            "ransomware": ("Security Incident", "Malware/Ransomware"),
            "ddos": ("Infrastructure", "Network Outage"),
            "data breach": ("Security Incident", "Unauthorized Access"),
            "insider threat": ("Security Incident", "Policy Violation"),
            "supply chain": ("External Dependency", "Vendor Incident"),
            "misconfiguration": ("Infrastructure", "Configuration Error")
        }

        category, subcategory = category_map.get(event_type.lower(), ("Unclassified", "Other"))

        record = IncidentRecord(
            incident_id=incident_id,
            priority=priority,
            impact=priority_data["impact"],
            urgency=priority_data["urgency"],
            category=category,
            subcategory=subcategory,
            affected_cis=affected_services.split(", ") if affected_services else ["Unknown"],
            assignment_group="Business Continuity Management",
            escalation_path=escalation_map[priority],
            sla_clock_start=now.isoformat() + "Z",
            bcm_plan_status="ACTIVATED" if priority == "P1" else "MONITORING",
            emergency_change_required=priority == "P1"
        )

        return json.dumps(record.model_dump(), indent=2)


class ServiceCatalogTool(BaseTool):
    """Realistic service catalog with dependencies, DR strategy, and compliance"""
    name: str = "get_service_catalog"
    description: str = (
        "Returns comprehensive service catalog with RTO/RPO, dependencies, "
        "DR strategy, compliance requirements, and tier classification."
    )

    def _run(self) -> str:
        catalog = {
            "services": SERVICE_CATALOG,
            "tier_definitions": {
                "1": "Critical - Mission critical to bank operations",
                "2": "Important - Significant operational impact if down",
                "3": "Standard - Can operate degraded for 24+ hours"
            },
            "dr_strategies": {
                "Hot Standby": "Real-time replication, <5 min failover, lowest RPO",
                "Warm Standby": "Periodic sync, 30-60 min failover, moderate RPO",
                "Cold Standby": "Manual restore, 4-24 hour failover, highest RPO"
            }
        }
        return json.dumps(catalog, indent=2)


class CalculateImpactTool(BaseTool):
    """Realistic financial impact with time-based degradation curves and dependencies"""
    name: str = "calculate_impact"
    description: str = (
        "Calculates service impact including financial loss, SLA penalties, "
        "regulatory risk, and cascading effects using time-based degradation curves."
    )

    def _run(self, service: str, hours_down: float = 1.0, **kwargs) -> str:
        service_key = None
        for svc_name in SERVICE_CATALOG.keys():
            if service.lower() in svc_name.lower():
                service_key = svc_name
                break

        if not service_key:
            service_key = "Mobile Banking"  # fallback

        svc_data = SERVICE_CATALOG[service_key]

        # Time-based degradation: impact increases non-linearly
        # Hour 1: 1.0x, Hour 2: 1.5x, Hour 3: 2.2x, Hour 4: 3.0x
        degradation_curve = min(3.0, 1.0 + (hours_down * 0.7))

        # Calculate impacts
        direct_revenue_loss = svc_data["hourly_revenue"] * hours_down * degradation_curve
        sla_penalty_pct = min(50, hours_down * 5)  # 5% per hour up to 50%
        sla_penalty = (svc_data["hourly_revenue"] * hours_down) * (sla_penalty_pct / 100)

        # Regulatory risk based on compliance requirements
        regulatory_risk = 0
        if "PCI-DSS" in str(svc_data["compliance"]):
            regulatory_risk += hours_down * 50000  # $50k/hour PCI fine risk
        if "SOX" in str(svc_data["compliance"]):
            regulatory_risk += hours_down * 100000  # $100k/hour SOX impact
        if "GDPR" in str(svc_data["compliance"]):
            regulatory_risk += hours_down * 75000  # $75k/hour GDPR exposure

        # Reputational damage (increases with time and customer base)
        reputation_score = min(100, int((svc_data["customers"] / 10000) * (hours_down / 4)))

        # Customer churn probability (low initially, high after 4+ hours)
        churn_probability = min(95, (hours_down - 1) * 15) if hours_down > 1 else 0

        # Cascading impact on dependent services (degraded to 60%)
        cascading_impacts = {}
        for dep_service in svc_data["dependencies"]:
            cascading_impacts[dep_service] = 0.60 * direct_revenue_loss

        analysis = ServiceImpactAnalysis(
            service_name=service_key,
            customers_impacted=svc_data["customers"],
            hourly_revenue_loss=direct_revenue_loss,
            cumulative_financial_impact=direct_revenue_loss,
            sla_penalty_exposure=sla_penalty,
            regulatory_fine_risk=regulatory_risk,
            regulatory_body="PCI-DSS, SOX, GDPR" if svc_data["compliance"] else "None",
            reputational_damage_score=reputation_score,
            customer_churn_probability_pct=churn_probability,
            time_of_day_multiplier=1.5,  # Assume peak hours
            cascading_impact_on_dependencies=cascading_impacts
        )

        return json.dumps(analysis.model_dump(), indent=2)


class FailoverServiceTool(BaseTool):
    """Realistic failover with variable outcomes and realistic timing"""
    name: str = "failover_service"
    description: str = (
        "Executes failover to DR site with realistic outcomes: success, partial, "
        "failed, or data loss. Includes health checks, replication lag, and validation."
    )

    def _run(self, service: str) -> str:
        service_key = None
        for svc_name in SERVICE_CATALOG.keys():
            if service.lower() in svc_name.lower():
                service_key = svc_name
                break

        if not service_key:
            service_key = service

        svc_data = SERVICE_CATALOG.get(service_key, {})
        dr_strategy = svc_data.get("dr_strategy", "Warm Standby")

        # Determine outcome based on DR strategy and last test result
        last_test = svc_data.get("dr_test_result", "PASSED")

        if dr_strategy == "Hot Standby" and "PASSED" in last_test:
            status = "success"
            duration = 15  # seconds
            replication_lag = 0
            data_loss = 0
        elif dr_strategy == "Warm Standby" and "PASSED" in last_test:
            status = "success"
            duration = 45  # seconds
            replication_lag = 10  # seconds
            data_loss = 0
        elif "FAILED" in last_test:
            status = "partial"
            duration = 300  # seconds
            replication_lag = 120  # seconds
            data_loss = 50
        else:
            status = "success"
            duration = 60
            replication_lag = 5
            data_loss = 0

        execution_steps = [
            {"step": 1, "action": "Pre-failover health check", "result": "success", "timestamp": "T+0s"},
            {"step": 2, "action": "Verify DR site capacity", "result": "success", "timestamp": f"T+{duration//3}s"},
            {"step": 3, "action": "Initiate failover protocol", "result": status, "timestamp": f"T+{duration//2}s"},
            {"step": 4, "action": "Validate service health in DR", "result": status, "timestamp": f"T+{duration}s"},
            {"step": 5, "action": "Update DNS/routing tables", "result": "success", "timestamp": f"T+{duration+5}s"}
        ]

        result = FailoverResult(
            service_name=service_key,
            status=status,
            pre_failover_health={
                "primary_cpu": 65,
                "primary_memory": 78,
                "replication_status": "In Sync" if replication_lag < 30 else "Lagging"
            },
            replication_lag_seconds=replication_lag,
            failover_duration_seconds=duration,
            execution_steps=execution_steps,
            validation_results={
                "service_responding": status in ["success", "partial"],
                "minimum_viable_capacity": status in ["success", "partial"],
                "data_integrity": status == "success"
            },
            manual_intervention_required=["Manual DNS verification"] if status != "success" else [],
            data_loss_records=data_loss
        )

        return json.dumps(result.model_dump(), indent=2)


class SendNotificationTool(BaseTool):
    """Audience-specific messaging with appropriate tone and detail level"""
    name: str = "send_notification"
    description: str = (
        "Sends audience-appropriate notifications with tailored tone, detail, "
        "and channel selection for customers, executives, technical teams, and regulators."
    )

    def _run(self, message: str, audience: str) -> str:
        audience_lower = audience.lower()
        channel = "email"

        # Generate audience-specific message
        if "customer" in audience_lower:
            formatted_msg = (
                f"🔔 SERVICE UPDATE: {message}\n\n"
                f"We are aware of an issue affecting your account. Our team is actively working to restore service. "
                f"Estimated resolution: 2-4 hours. We apologize for the inconvenience. "
                f"For updates, visit our status page: status.finserve.com"
            )
            channel = "email, SMS, status page"

        elif "executive" in audience_lower or "board" in audience_lower:
            formatted_msg = (
                f"⚠️  INCIDENT NOTIFICATION (EXECUTIVE BRIEFING):\n\n"
                f"{message}\n\n"
                f"FINANCIAL EXPOSURE: Estimated $2-5M revenue impact if unresolved within 4 hours\n"
                f"REGULATORY RISK: PCI-DSS notification may be required if data breach confirmed\n"
                f"DECISION POINTS: Approve DR activation? Notify regulators? Activate crisis comms?\n"
                f"Next update: 30 minutes"
            )
            channel = "email, war room bridge"

        elif "regulator" in audience_lower or "compliance" in audience_lower:
            formatted_msg = (
                f"REGULATORY NOTIFICATION: {message}\n\n"
                f"Per PCI-DSS 12.10 and FFIEC BCM Handbook requirements:\n"
                f"- Incident ID: INC-[TIMESTAMP]\n"
                f"- Event Classification: Major Incident\n"
                f"- Customer Data Impact: Under investigation\n"
                f"- GDPR 72-hour notification deadline: [DATETIME]\n"
                f"- Detailed incident report to follow within 24 hours\n"
                f"Primary Contact: Chief Risk Officer, risk@finserve.com"
            )
            channel = "email, secure portal"

        elif "technical" in audience_lower:
            formatted_msg = (
                f"🚨 INCIDENT ALERT (TECHNICAL TEAM):\n\n{message}\n\n"
                f"ACTION REQUIRED: Execute runbook INC-RESPONSE-001\n"
                f"Runbook: https://wiki.finserve.local/runbooks/incident-response\n"
                f"War Room Bridge: zoom.us/j/incident-war-room (PIN: 123456)\n"
                f"On-call escalation: PagerDuty - incident-commander@finserve.pagerduty.com"
            )
            channel = "email, Slack, war room"

        elif "vendor" in audience_lower or "partner" in audience_lower:
            formatted_msg = (
                f"INCIDENT COORDINATION NOTICE: {message}\n\n"
                f"Your services may be impacted. Per our SLA agreement:\n"
                f"- You must respond to coordination requests within 15 minutes\n"
                f"- Provide status updates every 30 minutes\n"
                f"- Estimated impact duration: TBD\n"
                f"Primary contact: partnerships@finserve.com"
            )
            channel = "email, API webhook"

        else:
            formatted_msg = f"NOTIFICATION: {message}"
            channel = "email"

        return f"📨 Message sent to {audience} via {channel}:\n\n{formatted_msg}"


class LogLessonTool(BaseTool):
    """Structured post-incident review with root cause and remediation tracking"""
    name: str = "log_lesson"
    description: str = (
        "Logs structured lessons learned using post-incident review format with "
        "root cause analysis, issue categorization, and remediation item tracking."
    )

    def _run(self, lesson: str) -> str:
        now = datetime.utcnow()

        # Categorize lesson
        category = "process"
        if any(x in lesson.lower() for x in ["tool", "system", "code", "configuration"]):
            category = "technology"
        elif any(x in lesson.lower() for x in ["communication", "training", "procedure", "manual"]):
            category = "process"
        elif any(x in lesson.lower() for x in ["staff", "team", "awareness", "knowledge"]):
            category = "people"

        # Generate remediation item
        remediation_id = f"REM-{now.strftime('%Y%m%d')}-{hashlib.md5(lesson.encode()).hexdigest()[:4].upper()}"
        due_date = (now + timedelta(days=30)).isoformat()

        pir_output = {
            "lesson_learned": lesson,
            "category": category,
            "framework_mapping": "ISO 22301 Section 8.4 (Continual Improvement)",
            "root_cause": "Insufficient testing" if "test" in lesson.lower() else "Process gap",
            "contributing_factors": ["Manual process", "Lack of automation"],
            "remediation_item": {
                "id": remediation_id,
                "description": f"Address root cause: {lesson[:60]}...",
                "owner": "ITSM Manager",
                "due_date": due_date,
                "priority": "High"
            },
            "related_frameworks": ["NIST CSF ID.RA", "ISO 27001 A.12.6.1"],
            "timeline_link": "Event occurred at T+0, detected at T+5min, mitigated at T+45min",
            "logged_timestamp": now.isoformat() + "Z"
        }

        return json.dumps(pir_output, indent=2)


# ============================================================================
# NEW TOOLS FOR PRODUCTION REALISM
# ============================================================================

class CheckServiceHealthTool(BaseTool):
    """Monitoring stack simulation (Datadog/PagerDuty/Grafana)"""
    name: str = "check_service_health"
    description: str = (
        "Queries monitoring stack for service health metrics: status, latency percentiles, "
        "error rates, throughput, resource utilization, active alerts, last deployment, on-call engineer."
    )

    def _run(self, service: str) -> str:
        service_key = None
        for svc_name in SERVICE_CATALOG.keys():
            if service.lower() in svc_name.lower():
                service_key = svc_name
                break

        if not service_key:
            service_key = service

        svc_data = SERVICE_CATALOG.get(service_key, {})

        # Simulate cascading degradation: if Payment Processing is down, others degrade
        status = "up"
        error_rate = 0.1
        p99_latency = 200

        if service_key == "Payment Processing":
            status = "degraded"
            error_rate = 2.5
            p99_latency = 850
        elif "Payment Processing" in svc_data.get("dependencies", []):
            status = "degraded"
            error_rate = 1.2
            p99_latency = 450

        health_data = {
            "service": service_key,
            "status": status,
            "uptime_pct": 99.2 if status == "up" else 95.5,
            "latency": {
                "p50_ms": 45,
                "p95_ms": 150,
                "p99_ms": p99_latency
            },
            "error_rate_pct": error_rate,
            "throughput_rps": 5000 if status == "up" else 1500,
            "resource_utilization": {
                "cpu_pct": 65,
                "memory_pct": 78,
                "disk_pct": 42
            },
            "active_alerts": ["High latency spike", "Error rate elevated"] if status != "up" else [],
            "last_deployment": "2026-04-12 14:30:00 UTC",
            "deployed_version": "v2.14.7",
            "oncall_engineer": "alice.chen@finserve.com"
        }

        return json.dumps(health_data, indent=2)


class QueryCmdbTool(BaseTool):
    """Configuration Management Database simulation"""
    name: str = "query_cmdb"
    description: str = (
        "Queries CMDB for configuration items, relationships, ownership, "
        "environment, last change date, and compliance status."
    )

    def _run(self, query: str) -> str:
        query_lower = query.lower()

        # Simple query parser
        if "relationship" in query_lower or "depend" in query_lower:
            cmdb_result = {
                "query": query,
                "results": [
                    {
                        "ci_name": "Mobile Banking",
                        "ci_type": "Application",
                        "relationships": ["depends_on:Payment Processing", "uses:Customer Portal"],
                        "owner": "Banking Services Team"
                    },
                    {
                        "ci_name": "Payment Processing",
                        "ci_type": "Application",
                        "relationships": ["supports:Mobile Banking", "supports:Online Transfers"],
                        "owner": "Payments Team"
                    }
                ]
            }
        else:
            cmdb_result = {
                "query": query,
                "results": [
                    {
                        "ci_name": SERVICE_CATALOG[service]["owner"],
                        "ci_type": "Service",
                        "owner": SERVICE_CATALOG[service]["owner"],
                        "environment": "production",
                        "last_change": "2026-04-10 09:15:00 UTC",
                        "compliance_status": "compliant",
                        "tags": ["critical", "pci-dss", "sox"]
                    }
                    for service in list(SERVICE_CATALOG.keys())[:3]
                ]
            }

        return json.dumps(cmdb_result, indent=2)


class ExecuteRunbookTool(BaseTool):
    """Operational runbook execution with step-level outcomes"""
    name: str = "execute_runbook"
    description: str = (
        "Executes predefined operational runbook with step-by-step results. "
        "Supports: network isolation, forensic snapshot, credential rotation, DNS failover."
    )

    def _run(self, runbook_id: str, parameters: str = "") -> str:
        rb = RUNBOOKS.get(runbook_id, RUNBOOKS["DNS_FAILOVER"])

        execution_log = {
            "runbook_id": runbook_id,
            "runbook_name": rb["name"],
            "status": "executing",
            "steps_executed": [],
            "overall_status": "success"
        }

        for i, step in enumerate(rb["steps"], 1):
            # Simulate most steps succeeding, some requiring manual intervention
            step_result = "completed" if i < len(rb["steps"]) else "requires_manual_review"

            execution_log["steps_executed"].append({
                "step_number": i,
                "action": step,
                "status": step_result,
                "timestamp": f"T+{i*30}s",
                "notes": "Manual intervention required" if step_result != "completed" else "Automated"
            })

        execution_log["manual_interventions_required"] = [
            step["action"] for step in execution_log["steps_executed"]
            if step["status"] == "requires_manual_review"
        ]

        return json.dumps(execution_log, indent=2)


class CheckComplianceStatusTool(BaseTool):
    """Multi-framework compliance assessment"""
    name: str = "check_compliance_status"
    description: str = (
        "Checks compliance status against PCI-DSS, SOX, GDPR, SOC 2, ISO 27001. "
        "Identifies impacted controls and regulatory notification deadlines."
    )

    def _run(self, incident_type: str = "general") -> str:
        now = datetime.utcnow()

        compliance_status = {
            "pci_dss": {
                "status": "potentially_impacted",
                "impacted_controls": ["3.4 (Data at Rest)", "6.5.10 (Broken Auth)"],
                "notification_deadline_hours": 72,
                "notification_body": "Security Event Report",
                "fee_exposure_dollars": 100000
            },
            "sox": {
                "status": "investigation_required",
                "impacted_controls": ["302 (Financial Reporting)", "906 (Officer Certification)"],
                "notification_deadline": (now + timedelta(days=30)).isoformat(),
                "audit_scope": "all"
            },
            "gdpr": {
                "status": "potential_breach",
                "articles_impacted": ["Article 5 (Lawful Basis)", "Article 32 (Security)"],
                "notification_deadline_hours": 72,
                "affected_data_subjects": 2_300_000
            },
            "iso_27001": {
                "status": "gap_identified",
                "controls_failing": ["A.12.6.1 (Management of changes)", "A.12.1.1 (Change control)"],
                "audit_scheduled": "2026-05-15"
            },
            "critical_actions": [
                "Preserve forensic evidence",
                "Notify Data Protection Officer",
                "Update incident response log",
                "Brief legal counsel"
            ]
        }

        return json.dumps(compliance_status, indent=2)


class AssessVendorImpactTool(BaseTool):
    """Third-party vendor/partner impact assessment"""
    name: str = "assess_vendor_impact"
    description: str = (
        "Evaluates impact on and from third-party vendors: affected contracts, "
        "SLA status, vendor communication, alternatives, and contractual penalties."
    )

    def _run(self, vendor_name: str = "PayBridge") -> str:
        vendor_assessment = {
            "vendor": vendor_name,
            "critical_services_provided": ["Payment Processing", "Card Network Access"],
            "current_sla_status": "violated" if vendor_name == "PayBridge" else "maintained",
            "sla_terms": {
                "availability_guarantee": "99.9%",
                "response_time_minutes": 15,
                "penalty_per_violation_pct": 5
            },
            "vendor_communication_status": "awaiting_status_update",
            "affected_contracts": [
                {
                    "contract_id": "V-2024-001",
                    "service": "Payment Processing",
                    "annual_value": 5_000_000,
                    "penalty_exposure": 250_000
                }
            ],
            "alternative_vendors": [
                {"name": "PayWave", "lead_time_days": 7},
                {"name": "TransactCore", "lead_time_days": 14}
            ],
            "recommended_actions": [
                "Invoke SLA escalation procedures",
                "Activate contingency vendor if available",
                "Document all impacts for contract renegotiation"
            ]
        }

        return json.dumps(vendor_assessment, indent=2)


class CoordinateWarRoomTool(BaseTool):
    """Incident war room / bridge call management"""
    name: str = "coordinate_war_room"
    description: str = (
        "Sets up and manages incident war room: tracks participants, decisions, "
        "action items, timeline, and escalation triggers."
    )

    def _run(self, action: str = "open", participants: str = "") -> str:
        now = datetime.utcnow()

        war_room_log = {
            "war_room_id": f"WR-{now.strftime('%Y%m%d%H%M%S')}",
            "status": "active",
            "bridge_url": "https://zoom.us/j/incident-war-room",
            "bridge_pin": "123456",
            "participants_joined": [
                "alice.chen@finserve.com (Incident Commander)",
                "bob.kumar@finserve.com (Technical Lead)",
                "carol.smith@finserve.com (Communications Manager)",
                "diana.lee@finserve.com (Business Continuity Manager)"
            ],
            "decisions_made": [
                {"timestamp": "T+5min", "decision": "Escalate to P1", "owner": "alice.chen@finserve.com"},
                {"timestamp": "T+15min", "decision": "Activate DR site", "owner": "bob.kumar@finserve.com"}
            ],
            "action_items": [
                {
                    "action": "Execute failover to DR",
                    "owner": "bob.kumar@finserve.com",
                    "due": "T+30min",
                    "status": "in_progress"
                },
                {
                    "action": "Prepare customer communication",
                    "owner": "carol.smith@finserve.com",
                    "due": "T+20min",
                    "status": "pending"
                }
            ],
            "escalation_triggers_hit": ["MTPD 6 hours", "Customer impact >1M", "Data breach suspected"],
            "timeline": [
                {"time": "T+0", "event": "Incident detected"},
                {"time": "T+5", "event": "War room opened"},
                {"time": "T+10", "event": "Initial assessment complete"}
            ]
        }

        return json.dumps(war_room_log, indent=2)


# ============================================================================
# TOOL INSTANTIATION
# ============================================================================

analyze_security_event = AnalyzeSecurityEventTool()
create_incident_record = CreateIncidentRecordTool()
get_service_catalog = ServiceCatalogTool()
calculate_impact = CalculateImpactTool()
failover_service = FailoverServiceTool()
send_notification = SendNotificationTool()
log_lesson = LogLessonTool()
check_service_health = CheckServiceHealthTool()
query_cmdb = QueryCmdbTool()
execute_runbook = ExecuteRunbookTool()
check_compliance_status = CheckComplianceStatusTool()
assess_vendor_impact = AssessVendorImpactTool()
coordinate_war_room = CoordinateWarRoomTool()
