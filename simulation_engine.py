"""
Multi-dimensional scoring engine for BCM and change-management runs.

Two scoring paths:

  Keyword-based (legacy):    Inspects the textual final_plan for evidence of
                             severity classification, BIA, containment, etc.
                             Used for incident scenarios.

  Artifact-based (new):      Inspects src.state.calendar (the change registry) and
                             src.state.cmdb after the run, scoring whether the
                             ITIL change lifecycle was actually followed — proper
                             state transitions, risk review present, calendar
                             checked, PIR with remediation items, etc.

Both paths feed into _calculate_overall_score, which weights dimensions per
scenario category.
"""
from __future__ import annotations

from typing import Any, Dict, List

try:
    from src import state
    from src.models import ChangeCategory, ChangeState
except Exception:  # pragma: no cover — engine should still work standalone
    state = None
    ChangeCategory = None
    ChangeState = None


CHANGE_SCENARIOS = {"standard_cert_rotation", "normal_db_upgrade", "failed_change_rollback"}


class SimulationEngine:
    """Multi-dimensional grader: keyword analysis for narrative, artifact analysis for governance."""

    def evaluate(self, final_plan: Any, scenario: str) -> dict:
        plan_text = self._concat_task_outputs(final_plan)
        plan_lower = plan_text.lower()

        scores = {
            "incident_classification": self._score_incident_classification(plan_lower, scenario),
            "business_impact_analysis": self._score_bia(plan_lower, scenario),
            "security_containment": self._score_containment(plan_lower, scenario),
            "disaster_recovery": self._score_recovery(plan_lower, scenario),
            "change_management": self._score_change_management(plan_lower),
            "change_governance": self._score_change_artifacts(scenario),
            "stakeholder_communication": self._score_communication(plan_lower, scenario),
            "regulatory_compliance": self._score_regulatory_compliance(plan_lower, scenario),
        }

        overall_kpi_score = self._calculate_overall_score(scores, scenario)

        result = {
            "scenario": scenario,
            "incident_classification_score": scores["incident_classification"],
            "business_impact_analysis_score": scores["business_impact_analysis"],
            "security_containment_score": scores["security_containment"],
            "disaster_recovery_score": scores["disaster_recovery"],
            "change_management_score": scores["change_management"],
            "change_governance_score": scores["change_governance"],
            "stakeholder_communication_score": scores["stakeholder_communication"],
            "regulatory_compliance_score": scores["regulatory_compliance"],
            "overall_kpi_score": overall_kpi_score,
        }

        self._print_evaluation(result)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _concat_task_outputs(final_plan: Any) -> str:
        """Combine outputs from all tasks if available; otherwise stringify."""
        chunks: List[str] = [str(final_plan)]
        for attr in ("tasks_output", "task_outputs", "tasks_outputs"):
            value = getattr(final_plan, attr, None)
            if value:
                for item in value:
                    raw = getattr(item, "raw", None) or getattr(item, "output", None) or str(item)
                    if raw:
                        chunks.append(str(raw))
                break
        return "\n".join(chunks)

    # ------------------------------------------------------------------
    # Keyword-based dimensions (used mainly for incident scenarios)
    # ------------------------------------------------------------------

    def _score_incident_classification(self, plan_lower: str, scenario: str) -> int:
        if scenario in CHANGE_SCENARIOS:
            return 100  # not applicable for change-only scenarios
        score = 0
        if any(x in plan_lower for x in ["p1", "priority 1", "critical", "catastrophic"]):
            score += 25
        elif any(x in plan_lower for x in ["p2", "priority 2", "major", "high"]):
            score += 20
        elif any(x in plan_lower for x in ["p3", "priority 3"]):
            score += 15
        else:
            score += 10
        score += 15 if "inc-" in plan_lower or "incident id" in plan_lower else 5
        if scenario in ["data_breach", "insider_threat", "ransomware"]:
            score += 20 if any(x in plan_lower for x in ["mitre", "att&ck", "tactic", "technique", "t1", "cve-"]) else 5
        else:
            score += 10
        score += 15 if ("escalation" in plan_lower or "bcm" in plan_lower) else 5
        score += 10 if "nist" in plan_lower else 2
        return min(100, score)

    def _score_bia(self, plan_lower: str, scenario: str) -> int:
        if scenario in CHANGE_SCENARIOS:
            return 100
        score = 0
        score += 20 if "rto" in plan_lower and "rpo" in plan_lower else (10 if ("rto" in plan_lower or "rpo" in plan_lower) else 0)
        score += 20 if any(x in plan_lower for x in ["$", "million", "revenue loss", "financial", "cost", "exposure"]) else 5
        score += 20 if any(x in plan_lower for x in ["pci-dss", "sox", "gdpr", "ffiec", "regulatory", "compliance"]) else 5
        score += 15 if any(x in plan_lower for x in ["priorit", "dependency", "cascade", "impact on", "affects"]) else 5
        score += 15 if any(x in plan_lower for x in ["sla", "penalty", "exposure", "customer churn", "reputation"]) else 3
        score += 10 if any(x in plan_lower for x in ["hour 1", "hour 2", "hour 3", "hours", "time-based", "degradation"]) else 2
        return min(100, score)

    def _score_containment(self, plan_lower: str, scenario: str) -> int:
        if scenario in CHANGE_SCENARIOS:
            return 100
        if scenario not in ["data_breach", "insider_threat", "ransomware", "supply_chain"]:
            return 75
        score = 0
        score += 20 if any(x in plan_lower for x in ["ioc", "indicator", "threat", "attack vector", "lateral"]) else 5
        score += 20 if any(x in plan_lower for x in ["isolat", "contain", "network isolation", "quarantine"]) else 5
        score += 25 if any(x in plan_lower for x in ["forensic", "evidence", "snapshot", "logs", "chain of custody"]) else 5
        score += 20 if any(x in plan_lower for x in ["credential", "rotate", "revoke", "access", "privilege"]) else 5
        score += 15 if any(x in plan_lower for x in ["eradication", "patch", "fix", "remediation", "malware removal"]) else 5
        return min(100, score)

    def _score_recovery(self, plan_lower: str, scenario: str) -> int:
        if scenario in CHANGE_SCENARIOS:
            return 100
        score = 0
        if any(x in plan_lower for x in ["within 4 hours", "under 240 minutes", "within 2 hours", "rto met"]):
            score += 25
        elif any(x in plan_lower for x in ["recovery time", "rto", "failover"]):
            score += 15
        else:
            score += 5
        score += 20 if any(x in plan_lower for x in ["rpo", "data loss", "replication", "point-in-time"]) else 5
        score += 20 if any(x in plan_lower for x in ["failover", "failed over", "secondary", "dr site", "disaster recovery"]) else 5
        score += 15 if any(x in plan_lower for x in ["validation", "health check", "verification", "confirm"]) else 5
        if all(x in plan_lower for x in ["mobile banking", "fraud detection", "failover"]):
            score += 15
        elif any(x in plan_lower for x in ["mobile banking", "payment", "transfer"]):
            score += 8
        else:
            score += 2
        score += 5 if any(x in plan_lower for x in ["minimum viable", "mvo", "degraded mode", "partial capacity"]) else 1
        return min(100, score)

    def _score_change_management(self, plan_lower: str) -> int:
        score = 0
        score += 25 if any(x in plan_lower for x in ["change", "cab", "emergency change", "change management"]) else 5
        score += 20 if any(x in plan_lower for x in ["document", "track", "log", "audit trail", "change log"]) else 5
        score += 20 if any(x in plan_lower for x in ["risk", "impact assessment", "test", "validate"]) else 5
        score += 15 if any(x in plan_lower for x in ["rollback", "contingency", "fallback", "undo", "backout"]) else 3
        score += 15 if any(x in plan_lower for x in ["validation", "health check", "verify"]) else 3
        return min(100, score)

    def _score_communication(self, plan_lower: str, scenario: str) -> int:
        if scenario in CHANGE_SCENARIOS:
            return 100
        score = 0
        score += 15 if any(x in plan_lower for x in ["customer", "notification", "user update", "status page"]) else 3
        score += 15 if any(x in plan_lower for x in ["executive", "board", "c-suite", "financial impact", "risk"]) else 3
        score += 15 if any(x in plan_lower for x in ["regulator", "compliance", "notification", "authority"]) else 3
        score += 15 if any(x in plan_lower for x in ["technical", "team", "runbook", "escalation", "war room"]) else 3
        score += 15 if any(x in plan_lower for x in ["email", "sms", "bridge", "slack", "status page", "call"]) else 3
        score += 10 if any(x in plan_lower for x in ["war room", "coordination", "bridge call", "participants"]) else 2
        return min(100, score)

    def _score_regulatory_compliance(self, plan_lower: str, scenario: str) -> int:
        score = 0
        framework_hits = sum(int(s in plan_lower) for s in ("nist", "itil", "iso 22301", "iso22301", "ffiec"))
        score += min(40, framework_hits * 10)
        if scenario in ["data_breach", "ransomware"]:
            score += 15 if ("pci-dss" in plan_lower or "pci dss" in plan_lower) else 5
        if scenario in ["data_breach", "insider_threat"]:
            score += 15 if ("gdpr" in plan_lower or "72-hour" in plan_lower or "72 hour" in plan_lower) else 5
        score += 10 if ("sox" in plan_lower or "sarbanes" in plan_lower) else 2
        score += 15 if any(x in plan_lower for x in ["deadline", "notification", "notify", "report", "disclosure"]) else 3
        score += 10 if any(x in plan_lower for x in ["control", "affected", "impact", "breach notification"]) else 2
        return min(100, score)

    # ------------------------------------------------------------------
    # Artifact-based dimension (the new realism check)
    # ------------------------------------------------------------------

    def _score_change_artifacts(self, scenario: str) -> int:
        """
        Inspect src.state.calendar to score the *correctness* of the change lifecycle
        for the change category. Standard changes skip technical/risk review by design
        (the template is the pre-approval), so they're scored against a different rubric
        than normal/emergency changes.
        """
        if state is None:
            return 0

        changes = state.calendar.all_changes()
        if not changes:
            return 0 if scenario in CHANGE_SCENARIOS else 50

        primary = self._primary_change(changes, scenario)
        if primary is None:
            return 0

        common = self._score_common_artifacts(changes)

        if primary.category == ChangeCategory.STANDARD:
            return min(100, common + self._score_standard_specifics(primary))
        if primary.category == ChangeCategory.EMERGENCY:
            return min(100, common + self._score_emergency_specifics(changes))
        return min(100, common + self._score_normal_specifics(changes))

    @staticmethod
    def _primary_change(changes, scenario):
        wanted = {
            "standard_cert_rotation": ChangeCategory.STANDARD,
            "normal_db_upgrade": ChangeCategory.NORMAL,
            "failed_change_rollback": ChangeCategory.NORMAL,
        }.get(scenario)
        if wanted is not None:
            for c in changes:
                if c.category == wanted:
                    return c
        return changes[0]

    @staticmethod
    def _score_common_artifacts(changes) -> int:
        """Points every change category should earn (max 50)."""
        terminal_states = {ChangeState.IMPLEMENTED, ChangeState.BACKED_OUT,
                           ChangeState.FAILED, ChangeState.CLOSED}
        score = 0
        if any(c.state in terminal_states for c in changes):
            score += 20
        if any(c.implementation_result and c.implementation_result.cmdb_updated for c in changes):
            score += 15
        good_pir = any(
            c.pir and (
                (c.pir.remediation_items and all(
                    r.owner and r.owner != "TBD" and r.due_date and r.priority
                    for r in c.pir.remediation_items
                )) or (c.category == ChangeCategory.STANDARD and c.pir.objective_met is not None)
            )
            for c in changes
        )
        if good_pir:
            score += 15
        return score

    @staticmethod
    def _score_standard_specifics(change) -> int:
        """Standard changes (max 50): template usage replaces individual reviews."""
        score = 0
        if change.standard_template_id:
            score += 25
        states_seen = {t.to_state for t in change.state_history} | {change.state}
        if {ChangeState.AT_CAB, ChangeState.APPROVED} <= states_seen:
            score += 15
        if change.pir and change.pir.objective_met is not None:
            score += 10
        return score

    @staticmethod
    def _score_normal_specifics(changes) -> int:
        """Normal changes (max 50): individual tech + risk + CAB + calendar checks."""
        score = 0
        if any(c.technical_review is not None for c in changes):
            score += 12
        if any(c.risk_review is not None for c in changes):
            score += 12
        cab_with_voters = [c for c in changes
                           if c.cab_decision and c.cab_decision.voting_members]
        if cab_with_voters:
            score += 10
        approver_chain_correct = False
        for c in changes:
            if c.risk_review and c.cab_decision and c.cab_decision.voting_members:
                required = {a.lower() for a in c.risk_review.required_approvers}
                cab_members = {m.lower() for m in c.cab_decision.voting_members}
                expanded = cab_members | {p.strip() for m in cab_members for p in m.split(",")}
                if required and required.issubset(expanded):
                    approver_chain_correct = True
                    break
        if approver_chain_correct:
            score += 8
        calendar_checked = any(
            c.risk_review and (c.risk_review.calendar_conflicts is not None
                               or c.risk_review.required_approvers)
            for c in changes
        )
        if calendar_checked:
            score += 8
        return score

    @staticmethod
    def _score_emergency_specifics(changes) -> int:
        """Emergency changes (max 50): abbreviated review + incident linkage."""
        score = 0
        if any(c.technical_review is not None for c in changes):
            score += 10
        if any(c.risk_review is not None for c in changes):
            score += 10
        if any(c.cab_decision and c.cab_decision.voting_members for c in changes):
            score += 10
        if any(c.linked_incident_id for c in changes if c.category == ChangeCategory.EMERGENCY):
            score += 10
        if any(c.pir for c in changes if c.category == ChangeCategory.EMERGENCY):
            score += 10
        return score

    # ------------------------------------------------------------------
    # Weights
    # ------------------------------------------------------------------

    def _calculate_overall_score(self, scores: dict, scenario: str) -> float:
        if scenario == "standard_cert_rotation":
            weights = {
                "incident_classification": 0.0, "business_impact_analysis": 0.0,
                "security_containment": 0.0, "disaster_recovery": 0.0,
                "change_management": 0.20, "change_governance": 0.65,
                "stakeholder_communication": 0.0, "regulatory_compliance": 0.15,
            }
        elif scenario == "normal_db_upgrade":
            weights = {
                "incident_classification": 0.0, "business_impact_analysis": 0.0,
                "security_containment": 0.0, "disaster_recovery": 0.0,
                "change_management": 0.20, "change_governance": 0.60,
                "stakeholder_communication": 0.0, "regulatory_compliance": 0.20,
            }
        elif scenario == "failed_change_rollback":
            weights = {
                "incident_classification": 0.0, "business_impact_analysis": 0.0,
                "security_containment": 0.0, "disaster_recovery": 0.0,
                "change_management": 0.20, "change_governance": 0.65,
                "stakeholder_communication": 0.0, "regulatory_compliance": 0.15,
            }
        elif scenario in ["data_breach", "insider_threat", "ransomware"]:
            weights = {
                "incident_classification": 0.13, "business_impact_analysis": 0.10,
                "security_containment": 0.22, "disaster_recovery": 0.18,
                "change_management": 0.05, "change_governance": 0.10,
                "stakeholder_communication": 0.13, "regulatory_compliance": 0.09,
            }
        elif scenario == "supply_chain":
            weights = {
                "incident_classification": 0.13, "business_impact_analysis": 0.13,
                "security_containment": 0.05, "disaster_recovery": 0.22,
                "change_management": 0.05, "change_governance": 0.10,
                "stakeholder_communication": 0.22, "regulatory_compliance": 0.10,
            }
        elif scenario == "cascading_failure":
            weights = {
                "incident_classification": 0.08, "business_impact_analysis": 0.13,
                "security_containment": 0.0, "disaster_recovery": 0.27,
                "change_management": 0.10, "change_governance": 0.15,
                "stakeholder_communication": 0.18, "regulatory_compliance": 0.09,
            }
        else:
            weights = {
                "incident_classification": 0.13, "business_impact_analysis": 0.13,
                "security_containment": 0.08, "disaster_recovery": 0.22,
                "change_management": 0.08, "change_governance": 0.12,
                "stakeholder_communication": 0.13, "regulatory_compliance": 0.11,
            }
        overall = sum(scores[d] * weights[d] for d in scores if d in weights)
        return round(overall, 1)

    # ------------------------------------------------------------------
    # Pretty print
    # ------------------------------------------------------------------

    def _print_evaluation(self, result: dict) -> None:
        print("\n" + "=" * 80)
        print("🔬 SIMULATION ENGINE EVALUATION")
        print("=" * 80)
        for key in [
            "incident_classification_score", "business_impact_analysis_score",
            "security_containment_score", "disaster_recovery_score",
            "change_management_score", "change_governance_score",
            "stakeholder_communication_score", "regulatory_compliance_score",
        ]:
            if key in result:
                score = result[key]
                label = key.replace("_score", "").replace("_", " ").title()
                bar = "█" * (int(score) // 10) + "░" * (10 - int(score) // 10)
                status = "✅" if score >= 80 else "⚠️ " if score >= 60 else "❌"
                print(f"{status} {label:.<40} {bar} {int(score)}/100")
        print("=" * 80)
        print(f"🎯 OVERALL KPI SCORE: {result['overall_kpi_score']}/100")
        print("=" * 80)
