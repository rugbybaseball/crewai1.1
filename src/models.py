"""
Pydantic models and enums for ITIL 4 change management.

These models give changes the same structural rigor that incidents already have via
IncidentRecord in tools.py — a single ChangeRecord object that flows through the CAB
lifecycle, with explicit state transitions auditable end-to-end.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ChangeCategory(str, Enum):
    STANDARD = "standard"      # Pre-approved, low-risk template (e.g. cert rotation)
    NORMAL = "normal"          # Planned, full CAB review
    EMERGENCY = "emergency"    # Incident-driven, abbreviated CAB


class ChangeState(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_TECHNICAL_REVIEW = "under_technical_review"
    UNDER_RISK_REVIEW = "under_risk_review"
    AT_CAB = "at_cab"
    APPROVED = "approved"
    REJECTED = "rejected"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    FAILED = "failed"
    BACKED_OUT = "backed_out"
    CLOSED = "closed"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


# Allowed forward transitions per state. Used by ChangeCalendar.transition() to
# enforce a real state machine instead of letting agents teleport between states.
ALLOWED_TRANSITIONS: Dict[ChangeState, List[ChangeState]] = {
    ChangeState.DRAFT: [ChangeState.SUBMITTED],
    ChangeState.SUBMITTED: [ChangeState.UNDER_TECHNICAL_REVIEW, ChangeState.REJECTED],
    ChangeState.UNDER_TECHNICAL_REVIEW: [ChangeState.UNDER_RISK_REVIEW, ChangeState.REJECTED],
    ChangeState.UNDER_RISK_REVIEW: [ChangeState.AT_CAB, ChangeState.REJECTED],
    ChangeState.AT_CAB: [ChangeState.APPROVED, ChangeState.REJECTED],
    ChangeState.APPROVED: [ChangeState.SCHEDULED, ChangeState.IN_PROGRESS],
    ChangeState.SCHEDULED: [ChangeState.IN_PROGRESS],
    ChangeState.IN_PROGRESS: [ChangeState.IMPLEMENTED, ChangeState.FAILED, ChangeState.BACKED_OUT],
    ChangeState.IMPLEMENTED: [ChangeState.CLOSED],
    ChangeState.FAILED: [ChangeState.BACKED_OUT, ChangeState.CLOSED],
    ChangeState.BACKED_OUT: [ChangeState.CLOSED],
    ChangeState.REJECTED: [ChangeState.CLOSED],
    ChangeState.CLOSED: [],
}


class StateTransition(BaseModel):
    """One step in a change's lifecycle audit trail."""
    from_state: Optional[ChangeState] = None
    to_state: ChangeState
    actor: str
    timestamp: str
    notes: str = ""


class RemediationItem(BaseModel):
    """An action arising from PIR or risk review."""
    id: str
    description: str
    owner: str
    due_date: str
    priority: str  # "Low" | "Medium" | "High" | "Critical"
    status: str = "open"


class TechnicalReview(BaseModel):
    """Output of the Technical Reviewer step."""
    reviewer: str
    decision: ReviewDecision
    backout_plan_validated: bool
    test_evidence_present: bool
    affected_cis_verified: bool
    implementation_plan_quality: str  # "incomplete" | "adequate" | "thorough"
    findings: List[str]
    timestamp: str


class RiskReview(BaseModel):
    """Output of the Risk & Compliance Reviewer step."""
    reviewer: str
    decision: ReviewDecision
    risk_level: RiskLevel
    probability_of_failure_pct: int
    impact_score: int  # 1-100
    risk_score: int  # probability * impact / 100
    kedb_matches: List[str]
    compliance_concerns: List[str]
    freeze_window_conflict: bool
    calendar_conflicts: List[str]
    required_approvers: List[str]
    findings: List[str]
    timestamp: str


class CABDecision(BaseModel):
    """Output of the CAB Chair step."""
    cab_chair: str
    decision: ReviewDecision
    voting_members: List[str]
    dissenting_members: List[str]
    conditions: List[str]
    scheduled_window_start: Optional[str] = None
    scheduled_window_end: Optional[str] = None
    timestamp: str
    rationale: str


class ImplementationResult(BaseModel):
    """Output of executing the change."""
    implementer: str
    started_at: str
    completed_at: str
    pre_check_results: Dict[str, Any]
    steps_executed: List[Dict[str, Any]]
    post_check_results: Dict[str, Any]
    cmdb_updated: bool
    backout_required: bool
    backout_executed: bool = False
    outcome: str  # "success" | "partial" | "failed" | "backed_out"


class PIRRecord(BaseModel):
    """Post-Implementation Review."""
    change_id: str
    objective_met: bool
    unexpected_side_effects: List[str]
    backout_was_needed: bool
    related_incidents_created: List[str]
    lessons_learned: List[str]
    remediation_items: List[RemediationItem]
    promote_to_standard: bool
    promote_rationale: str
    timestamp: str


class ChangeRecord(BaseModel):
    """ITIL 4 change record. Lives in ChangeCalendar; flows through ChangeState."""
    change_id: str
    category: ChangeCategory
    title: str
    description: str
    requester: str
    implementer: str
    affected_cis: List[str]
    linked_incident_id: Optional[str] = None
    state: ChangeState = ChangeState.DRAFT
    risk_level: Optional[RiskLevel] = None
    risk_score: Optional[int] = None
    backout_plan: str
    test_evidence: List[str] = Field(default_factory=list)
    planned_start: Optional[str] = None
    planned_end: Optional[str] = None
    standard_template_id: Optional[str] = None  # if category=standard
    state_history: List[StateTransition] = Field(default_factory=list)
    technical_review: Optional[TechnicalReview] = None
    risk_review: Optional[RiskReview] = None
    cab_decision: Optional[CABDecision] = None
    implementation_result: Optional[ImplementationResult] = None
    pir: Optional[PIRRecord] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class FreezeWindow(BaseModel):
    """A blackout period during which non-emergency changes are forbidden."""
    name: str
    start: str  # ISO datetime
    end: str    # ISO datetime
    reason: str
    allows_emergency: bool = True


class StandardChangeTemplate(BaseModel):
    """Pre-approved change template (category=standard skips full CAB)."""
    template_id: str
    title: str
    description: str
    typical_duration_minutes: int
    backout_plan: str
    risk_level: RiskLevel
    affected_ci_pattern: str  # e.g. "*_cert", "tier-2-*"
    times_used: int = 0
