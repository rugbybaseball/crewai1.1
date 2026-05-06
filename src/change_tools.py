"""
Change-management tools that read/write the named context layers.

Each tool returns JSON so agents can parse it back. Tools mutate shared state
(src/state.py singletons), so the technical reviewer can find the RFC the
requester just submitted, the CAB Chair can find the risk review's score, etc.

Naming convention: tool name maps 1:1 to the ITIL change activity it performs.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from crewai.tools import BaseTool

from src import state
from src.models import (
    ChangeCategory,
    ChangeRecord,
    ChangeState,
    CABDecision,
    ImplementationResult,
    PIRRecord,
    RemediationItem,
    ReviewDecision,
    RiskLevel,
    RiskReview,
    StandardChangeTemplate,
    TechnicalReview,
)


def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _gen_change_id(category: ChangeCategory, seed: str) -> str:
    h = hashlib.md5(f"{category.value}{seed}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:5].upper()
    prefix = {ChangeCategory.STANDARD: "STD", ChangeCategory.NORMAL: "CHG", ChangeCategory.EMERGENCY: "EMR"}[category]
    return f"{prefix}-{datetime.utcnow().strftime('%Y%m%d')}-{h}"


def _split_csv(s: str) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in re.split(r"[,;]", s) if x.strip()]


# ---------------------------------------------------------------------------
# RFC submission
# ---------------------------------------------------------------------------


class SubmitRFCTool(BaseTool):
    name: str = "submit_rfc"
    description: str = (
        "Submit a Request for Change (RFC) into the change calendar. "
        "Creates a formal ChangeRecord with a unique change_id and transitions DRAFT -> SUBMITTED. "
        "Use category='emergency' for incident-driven changes, 'normal' for planned changes "
        "needing full CAB review, or 'standard' for pre-approved templates (provide standard_template_id). "
        "affected_cis is a comma-separated list of CI names. "
        "Returns the ChangeRecord as JSON including the assigned change_id, which downstream "
        "reviewers and implementers MUST reference."
    )

    def _run(
        self,
        title: str,
        description: str,
        category: str,
        requester: str,
        implementer: str,
        affected_cis: str,
        backout_plan: str,
        linked_incident_id: str = "",
        test_evidence: str = "",
        planned_start: str = "",
        planned_end: str = "",
        standard_template_id: str = "",
    ) -> str:
        try:
            cat = ChangeCategory(category.lower().strip())
        except ValueError:
            return json.dumps({"error": f"Invalid category '{category}'. Use standard, normal, or emergency."})

        cis = _split_csv(affected_cis)
        if not cis:
            return json.dumps({"error": "affected_cis cannot be empty — list at least one CI"})

        change_id = _gen_change_id(cat, title)
        record = ChangeRecord(
            change_id=change_id,
            category=cat,
            title=title,
            description=description,
            requester=requester,
            implementer=implementer,
            affected_cis=cis,
            backout_plan=backout_plan,
            test_evidence=_split_csv(test_evidence),
            linked_incident_id=linked_incident_id or None,
            planned_start=planned_start or None,
            planned_end=planned_end or None,
            standard_template_id=standard_template_id or None,
        )
        state.calendar.add_change(record)
        state.calendar.transition(change_id, ChangeState.SUBMITTED, actor=requester, notes="RFC submitted")

        if cat is ChangeCategory.STANDARD and standard_template_id:
            tpl = state.calendar.get_template(standard_template_id)
            if tpl:
                state.calendar.transition(change_id, ChangeState.UNDER_TECHNICAL_REVIEW,
                                          actor="System", notes="Standard template path — automated routing")
                state.calendar.transition(change_id, ChangeState.UNDER_RISK_REVIEW,
                                          actor="System", notes="Pre-approved risk profile")
                state.calendar.transition(change_id, ChangeState.AT_CAB,
                                          actor="System", notes="Pre-approved by template")
                state.calendar.transition(change_id, ChangeState.APPROVED,
                                          actor="System", notes=f"Auto-approved via {standard_template_id}")
                tpl.times_used += 1

        result = state.calendar.get_change(change_id)
        return result.model_dump_json(indent=2) if result else json.dumps({"error": "submission failed"})


# ---------------------------------------------------------------------------
# Technical review
# ---------------------------------------------------------------------------


class ReviewRFCTechnicalTool(BaseTool):
    name: str = "review_rfc_technical"
    description: str = (
        "Conduct technical review of a submitted RFC. The Technical Reviewer validates the "
        "implementation plan, backout plan, test evidence, and CI scope. "
        "decision must be 'approve', 'reject', or 'request_changes'. "
        "findings is a comma-separated list of specific concerns or validations. "
        "Returns the updated ChangeRecord as JSON. Transitions the change to UNDER_RISK_REVIEW on approval."
    )

    def _run(
        self,
        change_id: str,
        reviewer: str,
        decision: str,
        findings: str = "",
        backout_plan_validated: bool = True,
        test_evidence_present: bool = True,
        affected_cis_verified: bool = True,
        implementation_plan_quality: str = "adequate",
    ) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})

        try:
            dec = ReviewDecision(decision.lower().strip())
        except ValueError:
            return json.dumps({"error": f"Invalid decision '{decision}'. Use approve, reject, or request_changes."})

        if ch.state is not ChangeState.SUBMITTED:
            from_state = ChangeState.SUBMITTED
            xn = state.calendar.transition(change_id, ChangeState.UNDER_TECHNICAL_REVIEW,
                                           actor=reviewer, notes="Picked up by Technical Reviewer")
            if not xn["ok"] and ch.state is not ChangeState.UNDER_TECHNICAL_REVIEW:
                return json.dumps({"error": xn["error"], "current_state": ch.state.value})
        else:
            state.calendar.transition(change_id, ChangeState.UNDER_TECHNICAL_REVIEW,
                                      actor=reviewer, notes="Technical review begins")

        ch.technical_review = TechnicalReview(
            reviewer=reviewer,
            decision=dec,
            backout_plan_validated=backout_plan_validated,
            test_evidence_present=test_evidence_present,
            affected_cis_verified=affected_cis_verified,
            implementation_plan_quality=implementation_plan_quality,
            findings=_split_csv(findings),
            timestamp=_now(),
        )

        if dec is ReviewDecision.APPROVE:
            state.calendar.transition(change_id, ChangeState.UNDER_RISK_REVIEW,
                                      actor=reviewer, notes="Technical review passed")
        elif dec is ReviewDecision.REJECT:
            state.calendar.transition(change_id, ChangeState.REJECTED,
                                      actor=reviewer, notes=f"Rejected at technical review: {findings}")

        return ch.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Risk & compliance review
# ---------------------------------------------------------------------------


class ReviewRFCRiskTool(BaseTool):
    name: str = "review_rfc_risk"
    description: str = (
        "Conduct risk & compliance review of a technically-reviewed RFC. "
        "Computes risk_score = probability_of_failure × impact_score / 100, classifies "
        "into low/medium/high/critical, queries KEDB for matching past failures on the "
        "same CIs, checks the change calendar for window and freeze-window conflicts, "
        "and identifies the required approver chain. Returns updated ChangeRecord as JSON."
    )

    def _run(
        self,
        change_id: str,
        reviewer: str,
        decision: str,
        compliance_concerns: str = "",
        findings: str = "",
    ) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})

        try:
            dec = ReviewDecision(decision.lower().strip())
        except ValueError:
            return json.dumps({"error": f"Invalid decision '{decision}'."})

        kedb_hits = []
        for ci in ch.affected_cis:
            kedb_hits.extend(state.kedb.query(ci_id=ci))
        kedb_match_ids = sorted({h["id"] for h in kedb_hits})

        n_cis = len(ch.affected_cis)
        kedb_factor = min(40, len(kedb_hits) * 10)
        complexity_factor = min(30, n_cis * 5)
        category_factor = {
            ChangeCategory.STANDARD: 5,
            ChangeCategory.NORMAL: 15,
            ChangeCategory.EMERGENCY: 35,
        }[ch.category]
        probability = min(95, kedb_factor + complexity_factor + category_factor)

        max_tier = 99
        for ci in ch.affected_cis:
            tier = state.services.tier(ci)
            if tier < max_tier:
                max_tier = tier
        impact = {1: 90, 2: 60, 3: 30, 99: 40}[max_tier if max_tier in (1, 2, 3) else 99]

        risk_score = round(probability * impact / 100)
        if risk_score >= 70:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 50:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 25:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        calendar_conflicts: List[str] = []
        freeze_conflict = False
        if ch.planned_start and ch.planned_end:
            for conflict in state.calendar.find_window_conflicts(
                ch.affected_cis, ch.planned_start, ch.planned_end, exclude_change_id=ch.change_id
            ):
                calendar_conflicts.append(
                    f"{conflict.get('change_id','?')} on {conflict.get('shared_cis',[])} "
                    f"({conflict.get('start','?')} - {conflict.get('end','?')})"
                )
            for fw in state.calendar.find_freeze_conflicts(ch.planned_start, ch.planned_end):
                if not (fw.allows_emergency and ch.category is ChangeCategory.EMERGENCY):
                    freeze_conflict = True
                    calendar_conflicts.append(f"FREEZE: {fw.name} ({fw.reason})")

        approvers = state.policy.required_approvers(risk_level)

        if ch.state is ChangeState.UNDER_TECHNICAL_REVIEW:
            state.calendar.transition(change_id, ChangeState.UNDER_RISK_REVIEW,
                                      actor=reviewer, notes="Routed from technical review")

        ch.risk_level = risk_level
        ch.risk_score = risk_score
        ch.risk_review = RiskReview(
            reviewer=reviewer,
            decision=dec,
            risk_level=risk_level,
            probability_of_failure_pct=probability,
            impact_score=impact,
            risk_score=risk_score,
            kedb_matches=kedb_match_ids,
            compliance_concerns=_split_csv(compliance_concerns),
            freeze_window_conflict=freeze_conflict,
            calendar_conflicts=calendar_conflicts,
            required_approvers=approvers,
            findings=_split_csv(findings),
            timestamp=_now(),
        )

        if dec is ReviewDecision.APPROVE and not freeze_conflict:
            state.calendar.transition(change_id, ChangeState.AT_CAB,
                                      actor=reviewer, notes=f"Risk={risk_level.value} ({risk_score})")
        elif dec is ReviewDecision.REJECT or freeze_conflict:
            note = "Freeze window conflict" if freeze_conflict else f"Rejected at risk review: {findings}"
            state.calendar.transition(change_id, ChangeState.REJECTED, actor=reviewer, notes=note)

        return ch.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# CAB decision
# ---------------------------------------------------------------------------


class CABDecisionTool(BaseTool):
    name: str = "cab_decision"
    description: str = (
        "Record the CAB's decision on a risk-reviewed RFC. The CAB Chair convenes voting members "
        "(Service Owner, Technical Reviewer, Risk & Compliance, plus CISO/CIO for critical risk). "
        "decision must be 'approve' or 'reject'. voting_members and dissenting_members are "
        "comma-separated. conditions are any conditions attached to approval. "
        "scheduled_window_start/end are ISO datetimes. Returns updated ChangeRecord."
    )

    def _run(
        self,
        change_id: str,
        cab_chair: str,
        decision: str,
        voting_members: str,
        rationale: str,
        dissenting_members: str = "",
        conditions: str = "",
        scheduled_window_start: str = "",
        scheduled_window_end: str = "",
    ) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})

        try:
            dec = ReviewDecision(decision.lower().strip())
        except ValueError:
            return json.dumps({"error": f"Invalid decision '{decision}'."})

        ch.cab_decision = CABDecision(
            cab_chair=cab_chair,
            decision=dec,
            voting_members=_split_csv(voting_members),
            dissenting_members=_split_csv(dissenting_members),
            conditions=_split_csv(conditions),
            scheduled_window_start=scheduled_window_start or None,
            scheduled_window_end=scheduled_window_end or None,
            timestamp=_now(),
            rationale=rationale,
        )

        if dec is ReviewDecision.APPROVE:
            state.calendar.transition(change_id, ChangeState.APPROVED,
                                      actor=cab_chair, notes=f"CAB approved with {len(_split_csv(voting_members))} members")
            if scheduled_window_start and scheduled_window_end:
                ch.planned_start = scheduled_window_start
                ch.planned_end = scheduled_window_end
        else:
            state.calendar.transition(change_id, ChangeState.REJECTED,
                                      actor=cab_chair, notes=rationale)

        return ch.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Schedule & query calendar
# ---------------------------------------------------------------------------


class ScheduleChangeTool(BaseTool):
    name: str = "schedule_change"
    description: str = (
        "Schedule an APPROVED change into a specific implementation window. "
        "Re-validates against the change calendar (window conflicts, freeze windows). "
        "If a conflict exists and the change is not emergency, returns an error and the "
        "calendar conflicts. Use ISO 8601 datetimes (e.g. 2026-04-29T02:00:00Z)."
    )

    def _run(self, change_id: str, planned_start: str, planned_end: str, scheduler: str) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})
        if ch.state is not ChangeState.APPROVED:
            return json.dumps({
                "error": f"Cannot schedule change in state {ch.state.value}. Must be APPROVED.",
            })

        window_conflicts = state.calendar.find_window_conflicts(
            ch.affected_cis, planned_start, planned_end, exclude_change_id=ch.change_id
        )
        freeze_conflicts = state.calendar.find_freeze_conflicts(planned_start, planned_end)
        blocking_freeze = [fw for fw in freeze_conflicts
                           if not (fw.allows_emergency and ch.category is ChangeCategory.EMERGENCY)]

        if window_conflicts or blocking_freeze:
            return json.dumps({
                "scheduled": False,
                "change_id": change_id,
                "window_conflicts": window_conflicts,
                "freeze_conflicts": [fw.model_dump() for fw in blocking_freeze],
                "remediation": "Pick another window, request override from CAB Chair, or escalate.",
            }, indent=2)

        ch.planned_start = planned_start
        ch.planned_end = planned_end
        state.calendar.transition(change_id, ChangeState.SCHEDULED,
                                  actor=scheduler, notes=f"Window {planned_start} -> {planned_end}")
        return json.dumps({
            "scheduled": True,
            "change_id": change_id,
            "planned_start": planned_start,
            "planned_end": planned_end,
        }, indent=2)


class QueryChangeCalendarTool(BaseTool):
    name: str = "query_change_calendar"
    description: str = (
        "Query the change calendar for window conflicts and freeze windows. "
        "affected_cis is a comma-separated list. Returns scheduled changes that would "
        "collide on shared CIs in the requested window plus any active freeze windows. "
        "Use this BEFORE picking an implementation window."
    )

    def _run(self, affected_cis: str, planned_start: str, planned_end: str) -> str:
        cis = _split_csv(affected_cis)
        window_conflicts = state.calendar.find_window_conflicts(cis, planned_start, planned_end)
        freeze_conflicts = state.calendar.find_freeze_conflicts(planned_start, planned_end)
        return json.dumps({
            "queried_cis": cis,
            "queried_window": {"start": planned_start, "end": planned_end},
            "window_conflicts": window_conflicts,
            "freeze_conflicts": [fw.model_dump() for fw in freeze_conflicts],
            "all_scheduled": [
                {
                    "change_id": ch.change_id,
                    "title": ch.title,
                    "cis": ch.affected_cis,
                    "start": ch.planned_start,
                    "end": ch.planned_end,
                    "state": ch.state.value,
                }
                for ch in state.calendar.all_changes()
                if ch.planned_start
            ],
        }, indent=2)


# ---------------------------------------------------------------------------
# Execute change & update CMDB
# ---------------------------------------------------------------------------


class ExecuteChangeTool(BaseTool):
    name: str = "execute_change"
    description: str = (
        "Execute a SCHEDULED or APPROVED change. Performs pre-checks, applies CMDB updates "
        "for the affected CIs (recording change_id), runs post-checks, and decides whether "
        "backout is needed. force_backout=true simulates a failed change that triggers "
        "the backout plan. Returns the implementation result and final state."
    )

    def _run(
        self,
        change_id: str,
        implementer: str,
        cmdb_updates: str = "",
        force_backout: bool = False,
    ) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})
        if ch.state not in (ChangeState.APPROVED, ChangeState.SCHEDULED):
            return json.dumps({
                "error": f"Cannot execute change in state {ch.state.value}. Must be APPROVED or SCHEDULED.",
            })

        state.calendar.transition(change_id, ChangeState.IN_PROGRESS,
                                  actor=implementer, notes="Implementation started")

        pre_checks = {ci: {"status": "healthy", "version": (state.cmdb.get(ci) or {}).get("current_version", "n/a")}
                      for ci in ch.affected_cis}

        steps = []
        cmdb_updated = False
        if cmdb_updates:
            for token in _split_csv(cmdb_updates):
                if "=" in token and ":" in token:
                    ci_part, kv = token.split(":", 1)
                    key, value = kv.split("=", 1)
                    state.cmdb.update(ci_part.strip(), change_id, {key.strip(): value.strip()})
                    steps.append({"step": len(steps) + 1, "action": f"Updated CMDB {ci_part}:{key}={value}",
                                  "status": "success", "timestamp": f"T+{(len(steps)+1)*30}s"})
                    cmdb_updated = True
        for ci in ch.affected_cis:
            steps.append({"step": len(steps) + 1, "action": f"Apply change to {ci}",
                          "status": "success", "timestamp": f"T+{(len(steps)+1)*30}s"})

        post_checks = {ci: {"status": "healthy" if not force_backout else "degraded"}
                       for ci in ch.affected_cis}

        if force_backout:
            state.calendar.transition(change_id, ChangeState.FAILED,
                                      actor=implementer, notes="Post-check failure")
            state.calendar.transition(change_id, ChangeState.BACKED_OUT,
                                      actor=implementer, notes="Backout plan executed")
            for ci in ch.affected_cis:
                state.cmdb.update(ci, change_id, {"state": "operational", "rollback_applied": True})
            outcome = "backed_out"
            backout_executed = True
        else:
            state.calendar.transition(change_id, ChangeState.IMPLEMENTED,
                                      actor=implementer, notes="Post-checks passed")
            outcome = "success"
            backout_executed = False

        ch.implementation_result = ImplementationResult(
            implementer=implementer,
            started_at=_now(),
            completed_at=_now(),
            pre_check_results=pre_checks,
            steps_executed=steps,
            post_check_results=post_checks,
            cmdb_updated=cmdb_updated or True,
            backout_required=force_backout,
            backout_executed=backout_executed,
            outcome=outcome,
        )
        return ch.model_dump_json(indent=2)


class UpdateCMDBTool(BaseTool):
    name: str = "update_cmdb"
    description: str = (
        "Directly update a Configuration Item in the CMDB, attributing the change to a change_id. "
        "attrs is a JSON object string of attributes to update (e.g. '{\"current_version\":\"v3.0\"}'). "
        "This is normally called as part of execute_change, but is exposed for cases where "
        "implementers need fine-grained control."
    )

    def _run(self, ci_id: str, change_id: str, attrs_json: str) -> str:
        try:
            attrs = json.loads(attrs_json)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"attrs_json must be valid JSON: {e}"})
        result = state.cmdb.update(ci_id, change_id, attrs)
        return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# KEDB query
# ---------------------------------------------------------------------------


class QueryKEDBTool(BaseTool):
    name: str = "query_kedb"
    description: str = (
        "Query the Known Error Database for past issues matching a CI and/or symptom. "
        "Use this BEFORE risk review to identify whether the proposed change touches CIs "
        "with a history of failures. Returns matched entries with root cause and workaround."
    )

    def _run(self, ci_id: str = "", symptom: str = "") -> str:
        hits = state.kedb.query(ci_id=ci_id, symptom=symptom)
        return json.dumps({"query": {"ci_id": ci_id, "symptom": symptom}, "results": hits}, indent=2)


# ---------------------------------------------------------------------------
# PIR & promotion to standard
# ---------------------------------------------------------------------------


class ConductPIRTool(BaseTool):
    name: str = "conduct_pir"
    description: str = (
        "Conduct Post-Implementation Review on an IMPLEMENTED, FAILED, or BACKED_OUT change. "
        "objective_met=true if the change achieved its stated outcome. unexpected_side_effects, "
        "lessons_learned, and remediation_items are comma-separated. "
        "promote_to_standard=true if this change was so routine and safe it should become a "
        "pre-approved template. Each remediation item has format 'description|owner|due_date_iso|priority'."
    )

    def _run(
        self,
        change_id: str,
        objective_met: bool,
        unexpected_side_effects: str = "",
        lessons_learned: str = "",
        remediation_items: str = "",
        promote_to_standard: bool = False,
        promote_rationale: str = "",
    ) -> str:
        ch = state.calendar.get_change(change_id)
        if ch is None:
            return json.dumps({"error": f"Change not found: {change_id}"})
        if ch.state not in (ChangeState.IMPLEMENTED, ChangeState.FAILED, ChangeState.BACKED_OUT):
            return json.dumps({
                "error": f"PIR requires an executed change. Current state: {ch.state.value}",
            })

        items: List[RemediationItem] = []
        for token in _split_csv(remediation_items):
            parts = [p.strip() for p in token.split("|")]
            if len(parts) >= 4:
                desc, owner, due, prio = parts[0], parts[1], parts[2], parts[3]
            else:
                desc, owner, due, prio = token, "TBD", (datetime.utcnow() + timedelta(days=30)).isoformat(), "Medium"
            rid = f"REM-{datetime.utcnow().strftime('%Y%m%d')}-{hashlib.md5(desc.encode()).hexdigest()[:4].upper()}"
            items.append(RemediationItem(id=rid, description=desc, owner=owner, due_date=due, priority=prio))

        ch.pir = PIRRecord(
            change_id=change_id,
            objective_met=objective_met,
            unexpected_side_effects=_split_csv(unexpected_side_effects),
            backout_was_needed=(ch.state is ChangeState.BACKED_OUT),
            related_incidents_created=[],
            lessons_learned=_split_csv(lessons_learned),
            remediation_items=items,
            promote_to_standard=promote_to_standard,
            promote_rationale=promote_rationale,
            timestamp=_now(),
        )

        state.kedb.record_change_outcome(change_id, {
            "outcome": ch.state.value,
            "objective_met": objective_met,
            "remediation_count": len(items),
        })

        if not objective_met or ch.state is ChangeState.BACKED_OUT:
            for ci in ch.affected_cis:
                state.kedb.add({
                    "id": f"KE-PIR-{change_id[-5:]}",
                    "ci_pattern": ci,
                    "symptom": (unexpected_side_effects.split(",")[0].strip()
                                if unexpected_side_effects else "implementation issue"),
                    "root_cause": (lessons_learned.split(",")[0].strip()
                                   if lessons_learned else "see PIR"),
                    "workaround": ch.backout_plan,
                    "permanent_fix_planned": items[0].due_date if items else "TBD",
                    "incidents_caused": 1,
                    "source_change_id": change_id,
                })

        if ch.state in (ChangeState.IMPLEMENTED, ChangeState.BACKED_OUT, ChangeState.FAILED):
            state.calendar.transition(change_id, ChangeState.CLOSED,
                                      actor="PIR", notes="PIR complete")

        return ch.model_dump_json(indent=2)


class PromoteToStandardTool(BaseTool):
    name: str = "promote_to_standard"
    description: str = (
        "Promote a successfully-completed change into a pre-approved Standard Change template, "
        "so future identical changes skip full CAB. Use only when the PIR explicitly recommended "
        "promotion. ci_pattern controls which future CIs the template applies to."
    )

    def _run(
        self,
        source_change_id: str,
        template_title: str,
        ci_pattern: str,
        typical_duration_minutes: int,
        risk_level: str,
    ) -> str:
        ch = state.calendar.get_change(source_change_id)
        if ch is None:
            return json.dumps({"error": f"Source change not found: {source_change_id}"})
        if not (ch.pir and ch.pir.promote_to_standard):
            return json.dumps({
                "error": "Source change does not have PIR.promote_to_standard=True. Conduct PIR first.",
            })
        try:
            level = RiskLevel(risk_level.lower().strip())
        except ValueError:
            return json.dumps({"error": f"Invalid risk_level '{risk_level}'."})

        template_id = f"STD-{datetime.utcnow().strftime('%Y%m%d')}-{hashlib.md5(template_title.encode()).hexdigest()[:4].upper()}"
        tpl = StandardChangeTemplate(
            template_id=template_id,
            title=template_title,
            description=f"Promoted from {source_change_id}: {ch.title}",
            typical_duration_minutes=typical_duration_minutes,
            backout_plan=ch.backout_plan,
            risk_level=level,
            affected_ci_pattern=ci_pattern,
            times_used=0,
        )
        state.calendar.add_template(tpl)
        return tpl.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Tool instantiation
# ---------------------------------------------------------------------------

submit_rfc = SubmitRFCTool()
review_rfc_technical = ReviewRFCTechnicalTool()
review_rfc_risk = ReviewRFCRiskTool()
cab_decision = CABDecisionTool()
schedule_change = ScheduleChangeTool()
query_change_calendar = QueryChangeCalendarTool()
execute_change = ExecuteChangeTool()
update_cmdb = UpdateCMDBTool()
query_kedb = QueryKEDBTool()
conduct_pir = ConductPIRTool()
promote_to_standard = PromoteToStandardTool()
