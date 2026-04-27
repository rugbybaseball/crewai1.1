"""
Production-grade BCM Simulation Engine with multi-dimensional scoring.

Evaluates incident response across 7 key dimensions:
1. Incident Classification & Severity Assessment
2. Business Impact Analysis
3. Security Containment & Forensics
4. Disaster Recovery Execution
5. Change Management Compliance
6. Stakeholder Communication
7. Regulatory Compliance
"""

import json


class SimulationEngine:
    """
    Multi-dimensional grading engine for BCM incident response evaluation.
    Scores against production ITIL 4, NIST CSF, and regulatory frameworks.
    """

    def evaluate(self, final_plan: str, scenario: str) -> dict:
        plan_lower = str(final_plan).lower()

        # Initialize scoring buckets
        scores = {
            "incident_classification": self._score_incident_classification(plan_lower, scenario),
            "business_impact_analysis": self._score_bia(plan_lower, scenario),
            "security_containment": self._score_containment(plan_lower, scenario),
            "disaster_recovery": self._score_recovery(plan_lower, scenario),
            "change_management": self._score_change_management(plan_lower),
            "stakeholder_communication": self._score_communication(plan_lower, scenario),
            "regulatory_compliance": self._score_regulatory_compliance(plan_lower, scenario),
        }

        # Calculate overall score
        overall_kpi_score = self._calculate_overall_score(scores, scenario)

        result = {
            "scenario": scenario,
            "incident_classification_score": scores["incident_classification"],
            "business_impact_analysis_score": scores["business_impact_analysis"],
            "security_containment_score": scores["security_containment"],
            "disaster_recovery_score": scores["disaster_recovery"],
            "change_management_score": scores["change_management"],
            "stakeholder_communication_score": scores["stakeholder_communication"],
            "regulatory_compliance_score": scores["regulatory_compliance"],
            "overall_kpi_score": overall_kpi_score,
        }

        self._print_evaluation(result, plan_lower)
        return result

    # ========================================================================
    # SCORING DIMENSIONS
    # ========================================================================

    def _score_incident_classification(self, plan_lower: str, scenario: str) -> int:
        """
        Scores proper incident classification following NIST CSF and ITIL 4.
        - Checks for severity assessment (P1-P4)
        - Verifies MITRE ATT&CK mapping (if security incident)
        - Confirms incident ID generation
        - Validates escalation path
        """
        score = 0

        # Severity/Priority classification
        if any(x in plan_lower for x in ["p1", "priority 1", "critical", "catastrophic"]):
            score += 25
        elif any(x in plan_lower for x in ["p2", "priority 2", "major", "high"]):
            score += 20
        elif any(x in plan_lower for x in ["p3", "priority 3"]):
            score += 15
        else:
            score += 10

        # Incident ID generation
        if "inc-" in plan_lower or "incident id" in plan_lower:
            score += 15
        else:
            score += 5

        # MITRE ATT&CK / Attack classification (bonus for security scenarios)
        if scenario in ["data_breach", "insider_threat", "ransomware"]:
            if any(x in plan_lower for x in ["mitre", "att&ck", "tactic", "technique", "t1", "cve-"]):
                score += 20
            else:
                score += 5
        else:
            score += 10

        # Escalation path and BCM activation
        if "escalation" in plan_lower or "bcm" in plan_lower or "bcm plan" in plan_lower:
            score += 15
        else:
            score += 5

        # NIST CSF reference
        if "nist" in plan_lower or "nist csf" in plan_lower:
            score += 10
        else:
            score += 2

        return min(100, score)

    def _score_bia(self, plan_lower: str, scenario: str) -> int:
        """
        Scores Business Impact Analysis quality.
        - Checks for RTO/RPO targets
        - Verifies financial impact quantification
        - Confirms regulatory exposure assessment
        - Validates service prioritization
        """
        score = 0

        # RTO/RPO targets identified
        if "rto" in plan_lower and "rpo" in plan_lower:
            score += 20
        elif "rto" in plan_lower or "rpo" in plan_lower:
            score += 10
        else:
            score += 0

        # Financial impact quantified
        if any(x in plan_lower for x in ["$", "million", "revenue loss", "financial", "cost", "exposure"]):
            score += 20
        else:
            score += 5

        # Regulatory/Compliance impact
        if any(x in plan_lower for x in ["pci-dss", "sox", "gdpr", "ffiec", "regulatory", "compliance"]):
            score += 20
        else:
            score += 5

        # Service prioritization/dependency analysis
        if any(x in plan_lower for x in ["priorit", "dependency", "cascade", "impact on", "affects"]):
            score += 15
        else:
            score += 5

        # SLA/Penalty assessment
        if any(x in plan_lower for x in ["sla", "penalty", "exposure", "customer churn", "reputation"]):
            score += 15
        else:
            score += 3

        # Time-based impact modeling
        if any(x in plan_lower for x in ["hour 1", "hour 2", "hour 3", "hours", "time-based", "degradation"]):
            score += 10
        else:
            score += 2

        return min(100, score)

    def _score_containment(self, plan_lower: str, scenario: str) -> int:
        """
        Scores security containment and forensic evidence preservation.
        Applies only to security-related scenarios.
        """
        if scenario not in ["data_breach", "insider_threat", "ransomware", "supply_chain"]:
            return 75  # Not applicable for non-security scenarios

        score = 0

        # IOC/Threat intelligence
        if any(x in plan_lower for x in ["ioc", "indicator", "threat", "attack vector", "lateral"]):
            score += 20
        else:
            score += 5

        # Isolation/Containment actions
        if any(x in plan_lower for x in ["isolat", "contain", "network isolation", "quarantine"]):
            score += 20
        else:
            score += 5

        # Forensic evidence preservation
        if any(x in plan_lower for x in ["forensic", "evidence", "snapshot", "logs", "chain of custody"]):
            score += 25
        else:
            score += 5

        # Credential rotation/access control
        if any(x in plan_lower for x in ["credential", "rotate", "revoke", "access", "privilege"]):
            score += 20
        else:
            score += 5

        # Eradication/Remediation recommendations
        if any(x in plan_lower for x in ["eradication", "patch", "fix", "remediation", "malware removal"]):
            score += 15
        else:
            score += 5

        return min(100, score)

    def _score_recovery(self, plan_lower: str, scenario: str) -> int:
        """
        Scores disaster recovery execution and validation.
        - Checks RTO achievements
        - Validates failover execution
        - Confirms post-failover health validation
        """
        score = 0

        # RTO target met
        if any(x in plan_lower for x in ["within 4 hours", "under 240 minutes", "within 2 hours", "rto met"]):
            score += 25
        elif any(x in plan_lower for x in ["recovery time", "rto", "failover"]):
            score += 15
        else:
            score += 5

        # RPO/Data loss assessment
        if any(x in plan_lower for x in ["rpo", "data loss", "replication", "point-in-time"]):
            score += 20
        else:
            score += 5

        # Failover execution steps
        if any(x in plan_lower for x in ["failover", "failed over", "secondary", "dr site", "disaster recovery"]):
            score += 20
        else:
            score += 5

        # Post-failover validation
        if any(x in plan_lower for x in ["validation", "health check", "verification", "confirm"]):
            score += 15
        else:
            score += 5

        # Services restored with specifics
        if all(x in plan_lower for x in ["mobile banking", "fraud detection", "failover"]):
            score += 15
        elif any(x in plan_lower for x in ["mobile banking", "payment", "transfer"]):
            score += 8
        else:
            score += 2

        # Minimum viable operations confirmed
        if any(x in plan_lower for x in ["minimum viable", "mvo", "degraded mode", "partial capacity"]):
            score += 5
        else:
            score += 1

        return min(100, score)

    def _score_change_management(self, plan_lower: str) -> int:
        """
        Scores change management compliance during recovery.
        - Verifies emergency change procedures followed
        - Checks change risk assessment
        - Validates rollback planning
        """
        score = 0

        # Change Advisory Board / Emergency CAB
        if any(x in plan_lower for x in ["change", "cab", "emergency change", "change management", "cac"]):
            score += 25
        else:
            score += 5

        # Change documentation/tracking
        if any(x in plan_lower for x in ["document", "track", "log", "audit trail", "change log"]):
            score += 20
        else:
            score += 5

        # Risk assessment
        if any(x in plan_lower for x in ["risk", "impact assessment", "test", "validate"]):
            score += 20
        else:
            score += 5

        # Rollback plan / Contingency
        if any(x in plan_lower for x in ["rollback", "contingency", "fallback", "undo"]):
            score += 15
        else:
            score += 3

        # Pre/post-change validation
        if any(x in plan_lower for x in ["validation", "health check", "verify"]):
            score += 15
        else:
            score += 3

        return min(100, score)

    def _score_communication(self, plan_lower: str, scenario: str) -> int:
        """
        Scores stakeholder communication quality.
        - Checks audience-specific messaging
        - Verifies communication channels
        - Validates communication timeline
        """
        score = 0

        # Customer communication
        if any(x in plan_lower for x in ["customer", "notification", "user update", "status page"]):
            score += 15
        else:
            score += 3

        # Executive/Board briefing
        if any(x in plan_lower for x in ["executive", "board", "c-suite", "financial impact", "risk"]):
            score += 15
        else:
            score += 3

        # Regulatory/Compliance notification
        if any(x in plan_lower for x in ["regulator", "compliance", "notification", "authority"]):
            score += 15
        else:
            score += 3

        # Technical team communication
        if any(x in plan_lower for x in ["technical", "team", "runbook", "escalation", "war room"]):
            score += 15
        else:
            score += 3

        # Communication channel diversity
        if any(x in plan_lower for x in ["email", "sms", "bridge", "slack", "status page", "call"]):
            score += 15
        else:
            score += 3

        # War room coordination
        if any(x in plan_lower for x in ["war room", "coordination", "bridge call", "participants"]):
            score += 10
        else:
            score += 2

        return min(100, score)

    def _score_regulatory_compliance(self, plan_lower: str, scenario: str) -> int:
        """
        Scores regulatory compliance and notification requirements.
        - Validates framework references (NIST CSF, ITIL, ISO 22301)
        - Checks regulatory notification deadlines met
        - Verifies control impact assessment
        """
        score = 0

        # Framework references
        framework_hits = 0
        if "nist" in plan_lower:
            framework_hits += 1
        if "itil" in plan_lower:
            framework_hits += 1
        if "iso 22301" in plan_lower or "iso22301" in plan_lower:
            framework_hits += 1
        if "ffiec" in plan_lower:
            framework_hits += 1

        score += framework_hits * 10

        # PCI-DSS specific (payment data scenarios)
        if scenario in ["data_breach", "ransomware"]:
            if "pci-dss" in plan_lower or "pci dss" in plan_lower:
                score += 15
            else:
                score += 5

        # GDPR specific (data breach scenarios)
        if scenario in ["data_breach", "insider_threat"]:
            if "gdpr" in plan_lower:
                score += 15
            elif "72" in plan_lower or "72-hour" in plan_lower:
                score += 15
            else:
                score += 5

        # SOX specific (financial reporting scenarios)
        if "sox" in plan_lower or "sarbanes" in plan_lower:
            score += 10
        else:
            score += 2

        # Notification deadline awareness
        if any(x in plan_lower for x in ["deadline", "notification", "notify", "report", "disclosure"]):
            score += 15
        else:
            score += 3

        # Control impact assessment
        if any(x in plan_lower for x in ["control", "affected", "impact", "breach notification"]):
            score += 10
        else:
            score += 2

        return min(100, score)

    # ========================================================================
    # OVERALL SCORING LOGIC
    # ========================================================================

    def _calculate_overall_score(self, scores: dict, scenario: str) -> float:
        """
        Calculates overall KPI score as weighted average of dimensions.
        Weights vary by scenario.
        """
        if scenario in ["data_breach", "insider_threat", "ransomware"]:
            # Security scenarios: heavy weight on containment and compliance
            weights = {
                "incident_classification": 0.15,
                "business_impact_analysis": 0.10,
                "security_containment": 0.25,
                "disaster_recovery": 0.20,
                "change_management": 0.05,
                "stakeholder_communication": 0.15,
                "regulatory_compliance": 0.10,
            }
        elif scenario == "supply_chain":
            # Vendor scenarios: heavy weight on vendor coordination and comms
            weights = {
                "incident_classification": 0.15,
                "business_impact_analysis": 0.15,
                "security_containment": 0.05,
                "disaster_recovery": 0.25,
                "change_management": 0.05,
                "stakeholder_communication": 0.25,
                "regulatory_compliance": 0.10,
            }
        elif scenario == "cascading_failure":
            # Operational scenarios: heavy weight on change management and recovery
            weights = {
                "incident_classification": 0.10,
                "business_impact_analysis": 0.15,
                "security_containment": 0.00,
                "disaster_recovery": 0.30,
                "change_management": 0.15,
                "stakeholder_communication": 0.20,
                "regulatory_compliance": 0.10,
            }
        else:
            # Default: balanced weights
            weights = {
                "incident_classification": 0.15,
                "business_impact_analysis": 0.15,
                "security_containment": 0.10,
                "disaster_recovery": 0.25,
                "change_management": 0.10,
                "stakeholder_communication": 0.15,
                "regulatory_compliance": 0.10,
            }

        # Weighted average
        overall = sum(
            scores[dim] * weights[dim]
            for dim in scores
            if dim in weights
        )

        return round(overall, 1)

    # ========================================================================
    # EVALUATION OUTPUT
    # ========================================================================

    def _print_evaluation(self, result: dict, plan_lower: str):
        """Pretty-prints evaluation results."""
        print("\n" + "=" * 80)
        print("🔬 SIMULATION ENGINE EVALUATION (Production-Grade BCM Scoring)")
        print("=" * 80)

        for key in [
            "incident_classification_score",
            "business_impact_analysis_score",
            "security_containment_score",
            "disaster_recovery_score",
            "change_management_score",
            "stakeholder_communication_score",
            "regulatory_compliance_score",
        ]:
            if key in result:
                score = result[key]
                label = key.replace("_score", "").replace("_", " ").title()
                bar = "█" * (score // 10) + "░" * (10 - score // 10)
                status = "✅" if score >= 80 else "⚠️ " if score >= 60 else "❌"
                print(f"{status} {label:.<40} {bar} {score}/100")

        print("=" * 80)
        print(f"🎯 OVERALL KPI SCORE: {result['overall_kpi_score']}/100")
        print("=" * 80)
