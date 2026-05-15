"""
Smoke test: drive change_tools and the simulation engine end-to-end without an LLM.

This validates:
  - All modules import cleanly
  - The state machine accepts the canonical ITIL transitions
  - submit -> tech review -> risk review -> CAB -> schedule -> execute -> PIR works
  - The simulation engine reads state.calendar artifacts and produces a score

Run:  python scripts/smoke_test.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from src import state
from src.change_tools import (
    submit_rfc, review_rfc_technical, review_rfc_risk, cab_decision,
    schedule_change, execute_change, conduct_pir, promote_to_standard,
    query_kedb, query_change_calendar,
    submit_license_request, route_license_request,
)
from src.models import ChangeState, RoutingDecision
from simulation_engine import SimulationEngine


def section(label: str) -> None:
    print(f"\n{'='*70}\n {label}\n{'='*70}")


def assert_field(obj: dict, field: str, expected=None) -> None:
    actual = obj.get(field)
    if expected is None:
        assert actual is not None, f"missing {field}: {obj}"
    else:
        assert actual == expected, f"{field}={actual!r} != {expected!r}"


def parse(json_str: str) -> dict:
    return json.loads(json_str)


def run_normal_change() -> str:
    section("NORMAL CHANGE: full CAB lifecycle")
    state.reset_state()

    print(query_kedb._run(ci_id="DB-PRIMARY-01"))
    print(query_change_calendar._run(
        affected_cis="DB-PRIMARY-01",
        planned_start="2026-05-04T03:00:00Z",
        planned_end="2026-05-04T05:00:00Z",
    ))

    submit_out = parse(submit_rfc._run(
        title="PostgreSQL 14.8 -> 15.5 minor upgrade",
        description="Apply vendor security advisory for DB-PRIMARY-01",
        category="normal",
        requester="alice.dba@finserve.com",
        implementer="alice.dba@finserve.com",
        affected_cis="DB-PRIMARY-01",
        backout_plan="Snapshot before upgrade; pg_restore from snapshot if post-checks fail",
        test_evidence="QA-2026-441",
        planned_start="2026-05-04T03:00:00Z",
        planned_end="2026-05-04T05:00:00Z",
    ))
    cid = submit_out["change_id"]
    assert_field(submit_out, "change_id")
    assert submit_out["state"] == ChangeState.SUBMITTED.value, submit_out["state"]
    print(f"  -> submitted as {cid}, state={submit_out['state']}")

    tech_out = parse(review_rfc_technical._run(
        change_id=cid, reviewer="dan.eng@finserve.com",
        decision="approve",
        findings="backout plan validated against KE-2025-031",
    ))
    assert tech_out["state"] == ChangeState.UNDER_RISK_REVIEW.value, tech_out["state"]
    print(f"  -> technical review: {tech_out['technical_review']['decision']}, state={tech_out['state']}")

    risk_out = parse(review_rfc_risk._run(
        change_id=cid, reviewer="rachel.risk@finserve.com",
        decision="approve",
        compliance_concerns="SOX 302 attestation needed post-upgrade",
        findings="risk score within tier-1 normal envelope",
    ))
    assert risk_out["state"] == ChangeState.AT_CAB.value, risk_out["state"]
    print(f"  -> risk review: level={risk_out['risk_review']['risk_level']} "
          f"score={risk_out['risk_review']['risk_score']} "
          f"approvers={risk_out['risk_review']['required_approvers']}")

    cab_out = parse(cab_decision._run(
        change_id=cid, cab_chair="cab.chair@finserve.com",
        decision="approve",
        voting_members="Service Owner, Technical Reviewer, Risk & Compliance, CAB Chair",
        rationale="Standard PG minor upgrade; tested in staging; backout plan rehearsed",
        scheduled_window_start="2026-05-04T03:00:00Z",
        scheduled_window_end="2026-05-04T05:00:00Z",
    ))
    assert cab_out["state"] == ChangeState.APPROVED.value, cab_out["state"]
    print(f"  -> CAB decision: {cab_out['cab_decision']['decision']} state={cab_out['state']}")

    sched_out = parse(schedule_change._run(
        change_id=cid, planned_start="2026-05-04T03:00:00Z",
        planned_end="2026-05-04T05:00:00Z",
        scheduler="cab.chair@finserve.com",
    ))
    assert sched_out["scheduled"] is True, sched_out
    print(f"  -> scheduled: {sched_out['scheduled']}")

    impl_out = parse(execute_change._run(
        change_id=cid, implementer="alice.dba@finserve.com",
        cmdb_updates="DB-PRIMARY-01:current_version=PostgreSQL 15.5",
    ))
    assert impl_out["state"] == ChangeState.IMPLEMENTED.value, impl_out["state"]
    print(f"  -> implementation outcome: {impl_out['implementation_result']['outcome']}")

    pir_out = parse(conduct_pir._run(
        change_id=cid, objective_met=True,
        unexpected_side_effects="",
        lessons_learned="staging fully reproduced production load patterns",
        remediation_items="Add automated minor-upgrade template|alice.dba@finserve.com|2026-06-04|Medium",
        promote_to_standard=True,
        promote_rationale="Procedure was rehearsed and ran cleanly; future minor upgrades can use this template",
    ))
    assert pir_out["state"] == ChangeState.CLOSED.value, pir_out["state"]
    print(f"  -> PIR: objective_met={pir_out['pir']['objective_met']} "
          f"items={len(pir_out['pir']['remediation_items'])}")

    promote_out = parse(promote_to_standard._run(
        source_change_id=cid,
        template_title="PostgreSQL minor version upgrade",
        ci_pattern="DB-*",
        typical_duration_minutes=120,
        risk_level="medium",
    ))
    assert_field(promote_out, "template_id")
    print(f"  -> promoted to standard: {promote_out['template_id']}")

    cmdb_after = state.cmdb.get("DB-PRIMARY-01")
    assert cmdb_after["current_version"] == "PostgreSQL 15.5", cmdb_after
    assert cmdb_after["last_change_id"] == cid, cmdb_after
    print(f"  -> CMDB: DB-PRIMARY-01 now {cmdb_after['current_version']} "
          f"(last_change_id={cmdb_after['last_change_id']})")

    return cid


def run_standard_change() -> str:
    section("STANDARD CHANGE: pre-approved template auto-promotes")
    state.reset_state()

    submit_out = parse(submit_rfc._run(
        title="Rotate AUTH-SVC-CERT before expiry",
        description="Pre-approved cert rotation",
        category="standard",
        requester="kira.singh@finserve.com",
        implementer="kira.singh@finserve.com",
        affected_cis="AUTH-SVC-CERT",
        backout_plan="Restore previous cert from PKI vault",
        standard_template_id="STD-CERT-001",
    ))
    cid = submit_out["change_id"]
    assert submit_out["state"] == ChangeState.APPROVED.value, submit_out["state"]
    print(f"  -> submitted as {cid}, auto-approved via template (state={submit_out['state']})")

    impl_out = parse(execute_change._run(
        change_id=cid, implementer="kira.singh@finserve.com",
        cmdb_updates="AUTH-SVC-CERT:current_version=expires 2027-06-15",
    ))
    assert impl_out["state"] == ChangeState.IMPLEMENTED.value
    print(f"  -> executed: {impl_out['implementation_result']['outcome']}")

    pir_out = parse(conduct_pir._run(
        change_id=cid, objective_met=True,
        lessons_learned="template ran clean; usage count now 48",
        remediation_items="",
        promote_to_standard=False,
    ))
    assert pir_out["state"] == ChangeState.CLOSED.value
    print(f"  -> PIR closed")

    return cid


def run_failed_change() -> str:
    section("FAILED CHANGE: backout exercised")
    state.reset_state()

    submit_out = parse(submit_rfc._run(
        title="API-GW v3.3.0 deploy",
        description="Minor API gateway version bump",
        category="normal",
        requester="leo.patel@finserve.com",
        implementer="leo.patel@finserve.com",
        affected_cis="API-GW-PROD",
        backout_plan="Blue/green swap back to v3.2.1",
        test_evidence="QA-2026-502",
        planned_start="2026-05-06T04:00:00Z",
        planned_end="2026-05-06T06:00:00Z",
    ))
    cid = submit_out["change_id"]
    parse(review_rfc_technical._run(change_id=cid, reviewer="dan.eng@finserve.com",
                                    decision="approve", findings="plan adequate"))
    parse(review_rfc_risk._run(change_id=cid, reviewer="rachel.risk@finserve.com",
                               decision="approve", findings="medium risk"))
    parse(cab_decision._run(
        change_id=cid, cab_chair="cab.chair@finserve.com",
        decision="approve",
        voting_members="Service Owner, Technical Reviewer, Risk & Compliance, CAB Chair",
        rationale="medium-risk routine deploy",
        scheduled_window_start="2026-05-06T04:00:00Z",
        scheduled_window_end="2026-05-06T06:00:00Z",
    ))
    parse(schedule_change._run(change_id=cid,
                               planned_start="2026-05-06T04:00:00Z",
                               planned_end="2026-05-06T06:00:00Z",
                               scheduler="cab.chair@finserve.com"))

    impl_out = parse(execute_change._run(
        change_id=cid, implementer="leo.patel@finserve.com",
        cmdb_updates="API-GW-PROD:current_version=v3.3.0",
        force_backout=True,
    ))
    assert impl_out["state"] == ChangeState.BACKED_OUT.value, impl_out["state"]
    print(f"  -> outcome={impl_out['implementation_result']['outcome']} "
          f"backout_executed={impl_out['implementation_result']['backout_executed']}")

    pir_out = parse(conduct_pir._run(
        change_id=cid, objective_met=False,
        unexpected_side_effects="health check endpoint returning 503 after deploy",
        lessons_learned="staging tests did not exercise the new health endpoint shape",
        remediation_items="Add health-endpoint contract test|leo.patel@finserve.com|2026-06-06|High",
        promote_to_standard=False,
    ))
    assert pir_out["state"] == ChangeState.CLOSED.value
    print(f"  -> PIR: backout_was_needed={pir_out['pir']['backout_was_needed']} "
          f"items={len(pir_out['pir']['remediation_items'])}")
    new_kedb = state.kedb.query(ci_id="API-GW-PROD")
    print(f"  -> KEDB now has {len(new_kedb)} entries for API-GW-PROD")
    return cid


def run_calendar_collision() -> None:
    section("CALENDAR COLLISION: freeze window blocks normal change")
    state.reset_state()

    submit_out = parse(submit_rfc._run(
        title="Risky deploy during month-end close",
        description="Should be rejected by risk review due to freeze window",
        category="normal",
        requester="alice.dba@finserve.com",
        implementer="alice.dba@finserve.com",
        affected_cis="DB-PRIMARY-01",
        backout_plan="snapshot/restore",
        test_evidence="QA-2026-999",
        planned_start="2026-04-29T02:00:00Z",
        planned_end="2026-04-29T04:00:00Z",
    ))
    cid = submit_out["change_id"]
    parse(review_rfc_technical._run(change_id=cid, reviewer="dan.eng@finserve.com",
                                    decision="approve", findings="OK technically"))
    risk_out = parse(review_rfc_risk._run(
        change_id=cid, reviewer="rachel.risk@finserve.com",
        decision="approve",
        compliance_concerns="SOX month-end close",
        findings="freeze window!",
    ))
    print(f"  -> risk review: state after = {risk_out['state']}")
    print(f"     calendar_conflicts = {risk_out['risk_review']['calendar_conflicts']}")
    print(f"     freeze_window_conflict = {risk_out['risk_review']['freeze_window_conflict']}")
    assert risk_out["state"] == ChangeState.REJECTED.value, risk_out["state"]
    assert risk_out["risk_review"]["freeze_window_conflict"] is True


def run_engine(scenario: str) -> None:
    section(f"SIMULATION ENGINE: scenario={scenario}")
    engine = SimulationEngine()
    engine.evaluate(final_plan="(driven directly by smoke test)", scenario=scenario)


# ---------------------------------------------------------------------------
# Phase 2: Software License Approval Router fixtures
# ---------------------------------------------------------------------------
#
# Four fixtures exercise the four Phase 1 outcomes WITHOUT an LLM. Each calls
# submit_license_request + route_license_request directly, then asserts the
# falsifiable success criteria on the resulting LicenseRequestRecord +
# ChangeRecord + CMDB + budget state.

def _submit_and_route(requester: str, role: str, dept: str, sku: str, seats: int = 1) -> dict:
    sub = parse(submit_license_request._run(
        requester=requester, requester_role=role, department=dept,
        license_sku=sku, seats=seats,
    ))
    assert "request_id" in sub, sub
    routed = parse(route_license_request._run(request_id=sub["request_id"]))
    return routed


def run_license_cheap_eligible_auto_approve() -> None:
    section("LICENSE FIXTURE 1: cheap + eligible -> auto-approve")
    state.reset_state()

    routed = _submit_and_route(
        requester="taylor.kim@finserve.com", role="engineer", dept="engineering",
        sku="ZOOM-PRO", seats=1,
    )

    assert routed["decision"] == RoutingDecision.AUTO_APPROVE.value, routed
    assert routed["pending_manager_approval"] is False, routed
    gate_names = {g["name"] for g in routed["gate_results"]}
    assert {"cost", "role_match", "budget"} <= gate_names, gate_names
    assert all(g["passed"] for g in routed["gate_results"]), routed["gate_results"]

    change = state.calendar.get_change(routed["change_id"])
    assert change.state == ChangeState.IMPLEMENTED, change.state
    ci = state.cmdb.get(change.affected_cis[0])
    assert ci and ci["last_change_id"] == routed["change_id"], ci
    assert ci["annual_cost"] == 150.0, ci

    print(f"  -> request {routed['request_id']} auto-approved in {routed['latency_ms']}ms")
    print(f"     CMDB allocation: {ci['current_version']} (annual_cost=${ci['annual_cost']})")


def run_license_expensive_eligible_to_manager() -> None:
    section("LICENSE FIXTURE 2: expensive + eligible -> manager (cost gate)")
    state.reset_state()

    routed = _submit_and_route(
        requester="jordan.lee@finserve.com", role="designer", dept="design",
        sku="ADOBE-CC-FULL", seats=1,
    )

    assert routed["decision"] == RoutingDecision.ROUTE_TO_MANAGER.value, routed
    assert routed["pending_manager_approval"] is True, routed
    cost_gate = next(g for g in routed["gate_results"] if g["name"] == "cost")
    role_gate = next(g for g in routed["gate_results"] if g["name"] == "role_match")
    assert cost_gate["passed"] is False, cost_gate
    assert role_gate["passed"] is True, role_gate

    change = state.calendar.get_change(routed["change_id"])
    assert change.state == ChangeState.UNDER_RISK_REVIEW, change.state
    print(f"  -> request {routed['request_id']} routed to manager (cost ${720*1:.2f} > $500)")


def run_license_ineligible_role_to_manager() -> None:
    section("LICENSE FIXTURE 3: ineligible role -> manager (role gate)")
    state.reset_state()

    # Designer requesting Salesforce CRM Enterprise — role-restricted to sales/account-manager.
    routed = _submit_and_route(
        requester="rene.ng@finserve.com", role="designer", dept="design",
        sku="SALESFORCE-CRM-ENT", seats=1,
    )

    assert routed["decision"] == RoutingDecision.ROUTE_TO_MANAGER.value, routed
    assert routed["pending_manager_approval"] is True, routed
    role_gate = next(g for g in routed["gate_results"] if g["name"] == "role_match")
    assert role_gate["passed"] is False, role_gate
    print(f"  -> request {routed['request_id']} routed to manager (role 'designer' not in eligible list)")


def run_license_enterprise_cap_breach() -> None:
    section("LICENSE FIXTURE 4: enterprise_cap breach -> manager (hard guard)")
    state.reset_state()

    # Pre-reserve seats so the catalog is 1 below cap; a 2-seat request will breach it.
    state.license_catalog.reserve_seats("ZOOM-PRO", 1499)

    routed = _submit_and_route(
        requester="ops.bot@finserve.com", role="operations", dept="operations",
        sku="ZOOM-PRO", seats=2,  # 1499 + 2 > 1500 cap
    )

    assert routed["decision"] == RoutingDecision.ROUTE_TO_MANAGER.value, routed
    assert routed["pending_manager_approval"] is True, routed
    cap_gate = next((g for g in routed["gate_results"] if g["name"] == "enterprise_cap"), None)
    assert cap_gate is not None and cap_gate["passed"] is False, routed["gate_results"]
    # Cost and role would have individually passed — the hard guard is what trips routing.
    cost_gate = next(g for g in routed["gate_results"] if g["name"] == "cost")
    role_gate = next(g for g in routed["gate_results"] if g["name"] == "role_match")
    assert cost_gate["passed"] is True and role_gate["passed"] is True, routed["gate_results"]
    print(f"  -> request {routed['request_id']} routed to manager (enterprise_cap guard)")


def run_license_engine_scoring() -> None:
    """Drive all four fixtures in one state, then let the engine score the run."""
    section("LICENSE FIXTURES: run all four, then score with SimulationEngine")
    state.reset_state()

    # Fixture A: cheap auto-approve
    _submit_and_route("taylor.kim@finserve.com", "engineer", "engineering",
                      "ZOOM-PRO", 1)
    # Fixture B: expensive -> manager
    _submit_and_route("jordan.lee@finserve.com", "designer", "design",
                      "ADOBE-CC-FULL", 1)
    # Fixture C: ineligible role -> manager
    _submit_and_route("rene.ng@finserve.com", "designer", "design",
                      "SALESFORCE-CRM-ENT", 1)
    # Fixture D: enterprise_cap breach -> manager
    state.license_catalog.reserve_seats("ZOOM-PRO", 1499)
    _submit_and_route("ops.bot@finserve.com", "operations", "operations",
                      "ZOOM-PRO", 2)

    engine = SimulationEngine()
    result = engine.evaluate(final_plan="(driven directly by smoke test)",
                             scenario="software_license_request")
    assert result["service_request_governance_score"] >= 80, result
    print(f"  -> service_request_governance_score = "
          f"{result['service_request_governance_score']} (>= 80 required)")


def main() -> None:
    run_normal_change()
    run_engine("normal_db_upgrade")

    run_standard_change()
    run_engine("standard_cert_rotation")

    run_failed_change()
    run_engine("failed_change_rollback")

    run_calendar_collision()

    # Phase 2: license-request fixtures
    run_license_cheap_eligible_auto_approve()
    run_license_expensive_eligible_to_manager()
    run_license_ineligible_role_to_manager()
    run_license_enterprise_cap_breach()
    run_license_engine_scoring()

    print("\nALL SMOKE TESTS PASSED ✓")


if __name__ == "__main__":
    main()
