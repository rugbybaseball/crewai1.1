"""
Six named context layers for ITSM change management.

Replaces the previous pattern of passing strings between tasks via CrewAI's
context=[task1, task2] parameter. Tools now read from and write to these
shared, queryable layers — which is what "context" actually means in ITIL.

Layers:
  - ServiceCatalogLayer:   read-mostly catalog (RTO/RPO, dependencies, compliance)
  - CMDBLayer:             mutable Configuration Items, CI relationships, current state
  - ChangeCalendarLayer:   change records, scheduled windows, freeze windows, std templates
  - PolicyRegistryLayer:   regulatory framework mappings, control->CI bindings
  - OperationalStateLayer: active incidents, on-call roster, monitoring status
  - KEDBLayer:             Known Error Database — past incidents/changes for risk scoring

Each layer is a module-level singleton — re-initialized at process start. Within
one `python main.py` run, tool calls share state, so an RFC submitted by one
agent is visible to the reviewer agent on the next task.
"""
from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.models import (
    ChangeRecord,
    ChangeState,
    FreezeWindow,
    LicenseRequestRecord,
    StandardChangeTemplate,
    StateTransition,
    ALLOWED_TRANSITIONS,
    RiskLevel,
)


# ---------------------------------------------------------------------------
# Layer 1: Service Catalog (read-mostly)
# ---------------------------------------------------------------------------

SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "Mobile Banking": {
        "tier": 1, "rto_hours": 4, "rpo_minutes": 15, "mtpd_hours": 6,
        "owner": "Banking Services Team", "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-15", "dr_test_result": "PASSED",
        "customers": 1_200_000, "hourly_revenue": 2_400_000,
        "dependencies": [], "compliance": ["PCI-DSS 3.4", "SOX 302", "GDPR 5.1"],
    },
    "Fraud Detection": {
        "tier": 1, "rto_hours": 2, "rpo_minutes": 5, "mtpd_hours": 3,
        "owner": "Risk Management Team", "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-10", "dr_test_result": "PASSED",
        "customers": 800_000, "hourly_revenue": 1_800_000,
        "dependencies": ["Payment Processing"],
        "compliance": ["PCI-DSS 6.5.10", "FFIEC BCM"],
    },
    "Online Transfers": {
        "tier": 1, "rto_hours": 4, "rpo_minutes": 15, "mtpd_hours": 6,
        "owner": "Core Banking Team", "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-12", "dr_test_result": "PASSED",
        "customers": 500_000, "hourly_revenue": 1_100_000,
        "dependencies": ["Mobile Banking", "Payment Processing"],
        "compliance": ["PCI-DSS 3.4", "SOX 302"],
    },
    "Payment Processing": {
        "tier": 1, "rto_hours": 1, "rpo_minutes": 1, "mtpd_hours": 2,
        "owner": "Payments Team", "dr_strategy": "Hot Standby",
        "last_dr_test": "2026-03-18", "dr_test_result": "PASSED",
        "customers": 2_000_000, "hourly_revenue": 3_500_000,
        "dependencies": [],
        "compliance": ["PCI-DSS 1.0", "PCI-DSS 3.2", "NACHA Rules"],
    },
    "Loan Management": {
        "tier": 2, "rto_hours": 8, "rpo_minutes": 30, "mtpd_hours": 12,
        "owner": "Lending Operations", "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-28", "dr_test_result": "PASSED",
        "customers": 400_000, "hourly_revenue": 500_000,
        "dependencies": ["Mobile Banking"],
        "compliance": ["SOX 302", "FDIC Requirements"],
    },
    "Investment Services": {
        "tier": 2, "rto_hours": 8, "rpo_minutes": 60, "mtpd_hours": 24,
        "owner": "Wealth Management", "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-20", "dr_test_result": "FAILED - Manual Recovery Needed",
        "customers": 200_000, "hourly_revenue": 300_000,
        "dependencies": ["Payment Processing"],
        "compliance": ["SEC 17a-3", "SOX 302"],
    },
    "Customer Portal": {
        "tier": 2, "rto_hours": 12, "rpo_minutes": 120, "mtpd_hours": 24,
        "owner": "Digital Services", "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-03-05", "dr_test_result": "PASSED",
        "customers": 1_500_000, "hourly_revenue": 0,
        "dependencies": ["Mobile Banking", "Online Transfers"],
        "compliance": ["GDPR 5.1", "WCAG 2.1"],
    },
    "Data Warehouse": {
        "tier": 3, "rto_hours": 24, "rpo_minutes": 360, "mtpd_hours": 48,
        "owner": "Analytics Team", "dr_strategy": "Cold Standby",
        "last_dr_test": "2026-01-30", "dr_test_result": "PASSED",
        "customers": 0, "hourly_revenue": 0,
        "dependencies": [], "compliance": ["GDPR 5.1", "Data Residency"],
    },
    "Compliance Reporting": {
        "tier": 3, "rto_hours": 4, "rpo_minutes": 15, "mtpd_hours": 8,
        "owner": "Compliance Team", "dr_strategy": "Warm Standby",
        "last_dr_test": "2026-02-14", "dr_test_result": "PASSED",
        "customers": 0, "hourly_revenue": 0,
        "dependencies": ["Data Warehouse"],
        "compliance": ["SOX 302", "FDIC 365.2"],
    },
}


class ServiceCatalogLayer:
    """Read-mostly: services, RTO/RPO, dependencies, compliance, DR strategy."""

    def __init__(self) -> None:
        self._catalog = deepcopy(SERVICE_CATALOG)

    def all(self) -> Dict[str, Dict[str, Any]]:
        return self._catalog

    def get(self, service: str) -> Optional[Dict[str, Any]]:
        for name, data in self._catalog.items():
            if service.lower() in name.lower() or name.lower() in service.lower():
                return data | {"name": name}
        return None

    def names(self) -> List[str]:
        return list(self._catalog.keys())

    def tier(self, service: str) -> int:
        d = self.get(service)
        return d.get("tier", 99) if d else 99


# ---------------------------------------------------------------------------
# Layer 2: CMDB (mutable)
# ---------------------------------------------------------------------------


class CMDBLayer:
    """Configuration Items with mutable state and change-attributed history."""

    def __init__(self, catalog: ServiceCatalogLayer) -> None:
        self._cis: Dict[str, Dict[str, Any]] = {}
        for service, data in catalog.all().items():
            self._cis[service] = {
                "ci_id": service,
                "ci_type": "Application",
                "owner": data["owner"],
                "environment": "production",
                "current_version": "v2.14.7",
                "last_change_id": None,
                "last_change_at": "2026-04-10T09:15:00Z",
                "compliance_status": "compliant",
                "tags": ["critical" if data["tier"] == 1 else "standard"],
                "relationships": [
                    {"type": "depends_on", "target": dep} for dep in data["dependencies"]
                ],
                "state": "operational",
            }
        infra_cis = [
            {"ci_id": "DB-PRIMARY-01", "ci_type": "Database", "owner": "DBA Team",
             "current_version": "PostgreSQL 14.8", "tags": ["pci-dss", "tier-1"]},
            {"ci_id": "AUTH-SVC-CERT", "ci_type": "TLS Certificate", "owner": "PKI Team",
             "current_version": "expires 2026-06-15", "tags": ["security"]},
            {"ci_id": "API-GW-PROD", "ci_type": "API Gateway", "owner": "Platform Team",
             "current_version": "v3.2.1", "tags": ["edge"]},
        ]
        for ci in infra_cis:
            self._cis[ci["ci_id"]] = {
                **ci,
                "environment": "production",
                "last_change_id": None,
                "last_change_at": "2026-03-20T12:00:00Z",
                "compliance_status": "compliant",
                "relationships": [],
                "state": "operational",
            }

    def get(self, ci_id: str) -> Optional[Dict[str, Any]]:
        if ci_id in self._cis:
            return self._cis[ci_id]
        for k, v in self._cis.items():
            if ci_id.lower() in k.lower():
                return v
        return None

    def update(self, ci_id: str, change_id: str, attrs: Dict[str, Any]) -> Dict[str, Any]:
        ci = self.get(ci_id)
        if ci is None:
            return {"error": f"CI not found: {ci_id}"}
        ci.update(attrs)
        ci["last_change_id"] = change_id
        ci["last_change_at"] = datetime.utcnow().isoformat() + "Z"
        return ci

    def add_ci(self, ci_id: str, ci_attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new Configuration Item. Used when a change creates a new CI
        (e.g., a license allocation entry produced by the Phase 2 router)."""
        if ci_id in self._cis:
            return self._cis[ci_id]
        self._cis[ci_id] = {
            "ci_id": ci_id,
            "environment": "production",
            "last_change_id": ci_attrs.get("last_change_id"),
            "last_change_at": datetime.utcnow().isoformat() + "Z",
            "compliance_status": "compliant",
            "relationships": [],
            "state": "operational",
            **ci_attrs,
        }
        return self._cis[ci_id]

    def find_relationships(self, ci_id: str) -> List[Dict[str, Any]]:
        ci = self.get(ci_id)
        if not ci:
            return []
        results = list(ci.get("relationships", []))
        for other_id, other in self._cis.items():
            for rel in other.get("relationships", []):
                if rel.get("target") == ci.get("ci_id"):
                    results.append({"type": f"reverse_{rel['type']}", "target": other_id})
        return results

    def find_by_owner(self, owner: str) -> List[Dict[str, Any]]:
        return [ci for ci in self._cis.values() if owner.lower() in ci["owner"].lower()]

    def all(self) -> Dict[str, Dict[str, Any]]:
        return self._cis


# ---------------------------------------------------------------------------
# Layer 3: Change Calendar (changes + freeze windows + std templates)
# ---------------------------------------------------------------------------


def _seed_freeze_windows() -> List[FreezeWindow]:
    """Realistic recurring freezes that scenarios can collide with."""
    today = datetime(2026, 4, 27)
    return [
        FreezeWindow(
            name="Month-end financial close",
            start=datetime(2026, 4, 28, 0, 0, 0).isoformat() + "Z",
            end=datetime(2026, 4, 30, 23, 59, 0).isoformat() + "Z",
            reason="SOX 302 controls — no production changes during close",
            allows_emergency=True,
        ),
        FreezeWindow(
            name="Quarterly regulatory reporting freeze",
            start=datetime(2026, 7, 1, 0, 0, 0).isoformat() + "Z",
            end=datetime(2026, 7, 7, 23, 59, 0).isoformat() + "Z",
            reason="Quarterly FFIEC reporting — heightened control",
            allows_emergency=True,
        ),
        FreezeWindow(
            name="Black Friday peak window",
            start=datetime(2026, 11, 26, 0, 0, 0).isoformat() + "Z",
            end=datetime(2026, 11, 30, 23, 59, 0).isoformat() + "Z",
            reason="Peak transaction volume — code freeze",
            allows_emergency=False,
        ),
    ]


def _seed_standard_templates() -> Dict[str, StandardChangeTemplate]:
    return {
        "STD-CERT-001": StandardChangeTemplate(
            template_id="STD-CERT-001",
            title="TLS certificate rotation",
            description="Rotate TLS certificate for a service before expiry. Pre-approved.",
            typical_duration_minutes=30,
            backout_plan="Restore previous cert from PKI vault; reload service.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="*-CERT",
            times_used=47,
        ),
        "STD-SCALE-001": StandardChangeTemplate(
            template_id="STD-SCALE-001",
            title="Horizontal autoscale adjustment",
            description="Adjust min/max instance count on tier-2 service.",
            typical_duration_minutes=15,
            backout_plan="Revert ASG min/max to previous values.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="tier-2-*",
            times_used=132,
        ),
        "STD-DNS-TTL-001": StandardChangeTemplate(
            template_id="STD-DNS-TTL-001",
            title="DNS TTL adjustment",
            description="Lower DNS TTL to 60s ahead of planned failover drill.",
            typical_duration_minutes=10,
            backout_plan="Restore TTL to 3600s.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="*",
            times_used=89,
        ),
        # Phase 2: pre-approved standard templates for low-cost, role-matched
        # software-license requests. The Auto-Approval Router uses these to
        # auto-approve in-bounds requests; out-of-bounds requests fall through
        # to manual manager review.
        "STD-LIC-COLLAB-001": StandardChangeTemplate(
            template_id="STD-LIC-COLLAB-001",
            title="Standard collaboration tool license (Slack/Zoom/Notion)",
            description="Pre-approved seat for any employee role; cost <= $500/year.",
            typical_duration_minutes=5,
            backout_plan="Revoke license via SaaS admin API.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="LIC-COLLAB-*",
            times_used=312,
        ),
        "STD-LIC-DESIGN-001": StandardChangeTemplate(
            template_id="STD-LIC-DESIGN-001",
            title="Designer/marketing creative license",
            description="Adobe Creative Cloud or equivalent for design/marketing roles only.",
            typical_duration_minutes=10,
            backout_plan="Revoke license via SaaS admin API.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="LIC-DESIGN-*",
            times_used=84,
        ),
        "STD-LIC-DEV-001": StandardChangeTemplate(
            template_id="STD-LIC-DEV-001",
            title="Developer IDE / language tooling license",
            description="JetBrains/VS Code paid features for developer roles only.",
            typical_duration_minutes=10,
            backout_plan="Revoke license via SaaS admin API.",
            risk_level=RiskLevel.LOW,
            affected_ci_pattern="LIC-DEV-*",
            times_used=156,
        ),
    }


class ChangeCalendarLayer:
    """Holds RFCs, scheduled windows, freeze windows, and pre-approved templates."""

    def __init__(self) -> None:
        self._changes: Dict[str, ChangeRecord] = {}
        self._freeze_windows: List[FreezeWindow] = _seed_freeze_windows()
        self._templates: Dict[str, StandardChangeTemplate] = _seed_standard_templates()
        self._scheduled: List[Dict[str, Any]] = [
            {
                "change_id": "CHG-PRE-001",
                "cis": ["Loan Management"],
                "start": "2026-04-29T02:00:00Z",
                "end": "2026-04-29T04:00:00Z",
                "title": "Loan engine quarterly upgrade",
            },
        ]

    def add_change(self, change: ChangeRecord) -> None:
        self._changes[change.change_id] = change

    def get_change(self, change_id: str) -> Optional[ChangeRecord]:
        return self._changes.get(change_id)

    def all_changes(self) -> List[ChangeRecord]:
        return list(self._changes.values())

    def transition(
        self,
        change_id: str,
        new_state: ChangeState,
        actor: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Enforce ChangeState transitions per ALLOWED_TRANSITIONS."""
        change = self._changes.get(change_id)
        if change is None:
            return {"ok": False, "error": f"Change not found: {change_id}"}
        allowed = ALLOWED_TRANSITIONS.get(change.state, [])
        if new_state not in allowed:
            return {
                "ok": False,
                "error": (
                    f"Illegal transition {change.state.value} -> {new_state.value}. "
                    f"Allowed: {[s.value for s in allowed]}"
                ),
            }
        prev = change.state
        change.state = new_state
        change.state_history.append(StateTransition(
            from_state=prev,
            to_state=new_state,
            actor=actor,
            timestamp=datetime.utcnow().isoformat() + "Z",
            notes=notes,
        ))
        return {"ok": True, "from": prev.value, "to": new_state.value}

    def find_window_conflicts(
        self, cis: List[str], start: str, end: str, exclude_change_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return scheduled changes that overlap on shared CIs."""
        try:
            req_start = datetime.fromisoformat(start.replace("Z", ""))
            req_end = datetime.fromisoformat(end.replace("Z", ""))
        except ValueError:
            return [{"error": "invalid window format; use ISO 8601"}]
        conflicts = []
        ci_set = set(cis)
        items: List[Dict[str, Any]] = list(self._scheduled)
        for ch in self._changes.values():
            if ch.planned_start and ch.planned_end and ch.change_id != exclude_change_id:
                if ch.state in (ChangeState.SCHEDULED, ChangeState.IN_PROGRESS, ChangeState.APPROVED):
                    items.append({
                        "change_id": ch.change_id,
                        "cis": ch.affected_cis,
                        "start": ch.planned_start,
                        "end": ch.planned_end,
                        "title": ch.title,
                    })
        for item in items:
            try:
                s = datetime.fromisoformat(item["start"].replace("Z", ""))
                e = datetime.fromisoformat(item["end"].replace("Z", ""))
            except (KeyError, ValueError):
                continue
            overlap = not (req_end <= s or req_start >= e)
            shared = ci_set & set(item["cis"])
            if overlap and shared:
                conflicts.append({**item, "shared_cis": sorted(shared)})
        return conflicts

    def find_freeze_conflicts(self, start: str, end: str) -> List[FreezeWindow]:
        try:
            req_start = datetime.fromisoformat(start.replace("Z", ""))
            req_end = datetime.fromisoformat(end.replace("Z", ""))
        except ValueError:
            return []
        hits = []
        for fw in self._freeze_windows:
            try:
                fs = datetime.fromisoformat(fw.start.replace("Z", ""))
                fe = datetime.fromisoformat(fw.end.replace("Z", ""))
            except ValueError:
                continue
            if not (req_end <= fs or req_start >= fe):
                hits.append(fw)
        return hits

    def get_template(self, template_id: str) -> Optional[StandardChangeTemplate]:
        return self._templates.get(template_id)

    def list_templates(self) -> List[StandardChangeTemplate]:
        return list(self._templates.values())

    def add_template(self, template: StandardChangeTemplate) -> None:
        self._templates[template.template_id] = template

    def freeze_windows(self) -> List[FreezeWindow]:
        return self._freeze_windows


# ---------------------------------------------------------------------------
# Layer 4: Policy Registry
# ---------------------------------------------------------------------------


class PolicyRegistryLayer:
    """Regulatory framework -> impacted controls per CI tag."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, Dict[str, Any]] = {
            "PCI-DSS": {
                "controls": ["1.0", "3.2", "3.4", "6.5.10", "12.10"],
                "notification_deadline_hours": 72,
                "applies_to_tags": ["pci-dss"],
                "control_descriptions": {
                    "3.4": "Data at rest encryption",
                    "6.5.10": "Broken authentication",
                    "12.10": "Incident response plan",
                },
            },
            "SOX": {
                "controls": ["302", "404", "906"],
                "notification_deadline_hours": 24 * 30,
                "applies_to_tags": ["sox", "tier-1"],
                "control_descriptions": {
                    "302": "Officer financial statement certification",
                    "404": "Internal control over financial reporting",
                },
            },
            "GDPR": {
                "controls": ["Article 5", "Article 32", "Article 33"],
                "notification_deadline_hours": 72,
                "applies_to_tags": ["gdpr", "personal-data"],
                "control_descriptions": {
                    "Article 5": "Lawful basis",
                    "Article 32": "Security of processing",
                    "Article 33": "Notification of personal data breach",
                },
            },
            "ISO_27001": {
                "controls": ["A.12.1.1", "A.12.6.1"],
                "notification_deadline_hours": 0,
                "applies_to_tags": ["security"],
                "control_descriptions": {
                    "A.12.1.1": "Documented operating procedures",
                    "A.12.6.1": "Management of technical vulnerabilities",
                },
            },
            "FFIEC": {
                "controls": ["BCM Handbook"],
                "notification_deadline_hours": 24,
                "applies_to_tags": ["tier-1", "financial"],
                "control_descriptions": {
                    "BCM Handbook": "Business continuity planning",
                },
            },
        }

    def frameworks_for_ci(self, ci_tags: List[str]) -> List[str]:
        hits = []
        tag_set = {t.lower() for t in ci_tags}
        for framework, data in self._frameworks.items():
            applies = {t.lower() for t in data["applies_to_tags"]}
            if applies & tag_set:
                hits.append(framework)
        return hits

    def get_framework(self, name: str) -> Optional[Dict[str, Any]]:
        return self._frameworks.get(name)

    def all(self) -> Dict[str, Dict[str, Any]]:
        return self._frameworks

    def required_approvers(self, risk_level: RiskLevel) -> List[str]:
        return {
            RiskLevel.LOW: ["Service Owner"],
            RiskLevel.MEDIUM: ["Service Owner", "Technical Reviewer"],
            RiskLevel.HIGH: ["Service Owner", "Technical Reviewer", "Risk & Compliance", "CAB Chair"],
            RiskLevel.CRITICAL: [
                "Service Owner", "Technical Reviewer", "Risk & Compliance",
                "CAB Chair", "CISO", "CIO",
            ],
        }[risk_level]


# ---------------------------------------------------------------------------
# Layer 5: Operational State
# ---------------------------------------------------------------------------


class OperationalStateLayer:
    """Active incidents, on-call roster, monitoring snapshot."""

    def __init__(self) -> None:
        self._active_incidents: Dict[str, Dict[str, Any]] = {}
        self._oncall: Dict[str, str] = {
            "Banking Services Team": "alice.chen@finserve.com",
            "Risk Management Team": "bob.kumar@finserve.com",
            "Core Banking Team": "carol.smith@finserve.com",
            "Payments Team": "diana.lee@finserve.com",
            "Lending Operations": "evan.park@finserve.com",
            "Wealth Management": "frank.gomez@finserve.com",
            "Digital Services": "gina.wu@finserve.com",
            "Analytics Team": "henry.osei@finserve.com",
            "Compliance Team": "iris.tanaka@finserve.com",
            "DBA Team": "jack.romero@finserve.com",
            "PKI Team": "kira.singh@finserve.com",
            "Platform Team": "leo.patel@finserve.com",
        }
        self._monitoring: Dict[str, Dict[str, Any]] = {}

    def register_incident(self, incident_id: str, attrs: Dict[str, Any]) -> None:
        self._active_incidents[incident_id] = attrs

    def active_incidents(self) -> List[Dict[str, Any]]:
        return list(self._active_incidents.values())

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self._active_incidents.get(incident_id)

    def oncall_for(self, owner: str) -> Optional[str]:
        for team, person in self._oncall.items():
            if owner.lower() in team.lower() or team.lower() in owner.lower():
                return person
        return None

    def set_monitoring(self, service: str, snapshot: Dict[str, Any]) -> None:
        self._monitoring[service] = snapshot

    def get_monitoring(self, service: str) -> Optional[Dict[str, Any]]:
        return self._monitoring.get(service)


# ---------------------------------------------------------------------------
# Layer 6: KEDB
# ---------------------------------------------------------------------------


class KEDBLayer:
    """Known Error Database — historical issues drive risk scoring."""

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = [
            {
                "id": "KE-2025-018",
                "ci_pattern": "Payment Processing",
                "symptom": "replication lag",
                "root_cause": "WAN bandwidth saturation during 02:00 UTC backup",
                "workaround": "Reschedule backup outside replication window",
                "permanent_fix_planned": "2026-Q3",
                "incidents_caused": 3,
            },
            {
                "id": "KE-2025-031",
                "ci_pattern": "DB-PRIMARY-01",
                "symptom": "concurrent backup lock contention",
                "root_cause": "Backup tool acquires exclusive lock blocking migration rollback",
                "workaround": "Disable backup during migration window",
                "permanent_fix_planned": "2026-Q2",
                "incidents_caused": 2,
            },
            {
                "id": "KE-2026-002",
                "ci_pattern": "AUTH-SVC-CERT",
                "symptom": "cert rotation breaks pinned mobile clients",
                "root_cause": "Old mobile app versions pin to retiring cert chain",
                "workaround": "Phased rollout + force-update banner",
                "permanent_fix_planned": "ongoing",
                "incidents_caused": 1,
            },
            {
                "id": "KE-2025-045",
                "ci_pattern": "Investment Services",
                "symptom": "DR failover requires manual recovery",
                "root_cause": "Warm standby database checkpoint script missing in DR site",
                "workaround": "Manual checkpoint + resync after failover",
                "permanent_fix_planned": "2026-Q2",
                "incidents_caused": 1,
            },
        ]
        self._post_change_records: List[Dict[str, Any]] = []

    def query(self, ci_id: str = "", symptom: str = "") -> List[Dict[str, Any]]:
        hits = []
        ci_l = ci_id.lower()
        symptom_l = symptom.lower()
        for entry in self._entries:
            ci_match = not ci_l or ci_l in entry["ci_pattern"].lower() or entry["ci_pattern"].lower() in ci_l
            sym_match = not symptom_l or any(
                token in entry["symptom"].lower()
                for token in re.findall(r"\w+", symptom_l)
            )
            if ci_match and (sym_match if symptom_l else True):
                hits.append(entry)
        return hits

    def add(self, entry: Dict[str, Any]) -> None:
        self._entries.append(entry)

    def record_change_outcome(self, change_id: str, outcome: Dict[str, Any]) -> None:
        self._post_change_records.append({"change_id": change_id, **outcome})

    def all_entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)


# ---------------------------------------------------------------------------
# Layer 7: License Catalog (Phase 2 — service-request scenario)
# ---------------------------------------------------------------------------
#
# SKU metadata for the Software License Approval Router. Each SKU declares:
#   - cost_per_seat_year: drives the cost gate (auto-threshold = $500)
#   - eligible_roles: drives the role-match gate
#   - enterprise_cap: ELA seat limit; auto-approval must NEVER exceed this
#                     regardless of cost (the second-order vendor true-up risk)
#   - template_id: the STD-LIC-* template used on auto-approval
#   - compliance_tags: feeds the policy layer (PII processors trigger GDPR review)


LICENSE_CATALOG: Dict[str, Dict[str, Any]] = {
    "ADOBE-CC-FULL": {
        "name": "Adobe Creative Cloud (All Apps)",
        "cost_per_seat_year": 720.0,
        "eligible_roles": ["designer", "marketing", "creative"],
        "enterprise_cap": 50,
        "template_id": "STD-LIC-DESIGN-001",
        "compliance_tags": [],
    },
    "ADOBE-ACROBAT-STD": {
        "name": "Adobe Acrobat Standard",
        "cost_per_seat_year": 180.0,
        "eligible_roles": ["*"],  # any role
        "enterprise_cap": 500,
        "template_id": "STD-LIC-COLLAB-001",
        "compliance_tags": [],
    },
    "JETBRAINS-IDEA-ULT": {
        "name": "JetBrains IntelliJ IDEA Ultimate",
        "cost_per_seat_year": 1000.0,
        "eligible_roles": ["developer", "engineer", "sre"],
        "enterprise_cap": 200,
        "template_id": "STD-LIC-DEV-001",
        "compliance_tags": [],
    },
    "SLACK-BUSINESS-PLUS": {
        "name": "Slack Business+ seat",
        "cost_per_seat_year": 180.0,
        "eligible_roles": ["*"],
        "enterprise_cap": 2000,
        "template_id": "STD-LIC-COLLAB-001",
        "compliance_tags": [],
    },
    "ZOOM-PRO": {
        "name": "Zoom Pro seat",
        "cost_per_seat_year": 150.0,
        "eligible_roles": ["*"],
        "enterprise_cap": 1500,
        "template_id": "STD-LIC-COLLAB-001",
        "compliance_tags": [],
    },
    "SALESFORCE-CRM-ENT": {
        "name": "Salesforce CRM Enterprise",
        "cost_per_seat_year": 1800.0,
        "eligible_roles": ["sales", "account-manager"],
        "enterprise_cap": 120,
        "template_id": "STD-LIC-COLLAB-001",
        "compliance_tags": ["personal-data", "gdpr"],
    },
}


class LicenseCatalogLayer:
    """Read-mostly catalog of license SKUs with cost, role eligibility, ELA caps."""

    AUTO_APPROVE_COST_THRESHOLD: float = 500.0  # Phase 1 success criterion

    def __init__(self) -> None:
        self._catalog = deepcopy(LICENSE_CATALOG)
        # seats_in_use is mutable — every auto-approved IMPLEMENTED request increments
        self._seats_in_use: Dict[str, int] = {sku: 0 for sku in self._catalog}

    def get(self, sku: str) -> Optional[Dict[str, Any]]:
        return self._catalog.get(sku.upper())

    def all_skus(self) -> List[str]:
        return list(self._catalog.keys())

    def role_eligible(self, sku: str, role: str) -> bool:
        meta = self.get(sku)
        if not meta:
            return False
        eligible = [r.lower() for r in meta["eligible_roles"]]
        if "*" in eligible:
            return True
        return role.lower() in eligible

    def seats_in_use(self, sku: str) -> int:
        return self._seats_in_use.get(sku.upper(), 0)

    def reserve_seats(self, sku: str, seats: int) -> int:
        """Increment in-use seat count (called on auto-approve IMPLEMENTED)."""
        sku_u = sku.upper()
        self._seats_in_use[sku_u] = self._seats_in_use.get(sku_u, 0) + seats
        return self._seats_in_use[sku_u]

    def would_exceed_enterprise_cap(self, sku: str, additional_seats: int) -> bool:
        meta = self.get(sku)
        if not meta:
            return False
        cap = meta.get("enterprise_cap")
        if cap is None:
            return False
        return (self.seats_in_use(sku) + additional_seats) > cap


# ---------------------------------------------------------------------------
# Layer 8: Budget (Phase 2)
# ---------------------------------------------------------------------------
#
# Per-department monthly software pool. The router checks headroom before
# auto-approving. The circuit-breaker fires when cumulative auto-approved
# spend exceeds 110% of forecast — the Phase 1 second-order failure mode.


DEPARTMENT_BUDGETS: Dict[str, Dict[str, float]] = {
    "engineering":   {"monthly_pool": 25000.0, "forecast": 22000.0, "spent": 0.0},
    "design":        {"monthly_pool": 8000.0,  "forecast": 7000.0,  "spent": 0.0},
    "marketing":     {"monthly_pool": 10000.0, "forecast": 9000.0,  "spent": 0.0},
    "sales":         {"monthly_pool": 20000.0, "forecast": 18000.0, "spent": 0.0},
    "operations":    {"monthly_pool": 6000.0,  "forecast": 5000.0,  "spent": 0.0},
    "finance":       {"monthly_pool": 5000.0,  "forecast": 4500.0,  "spent": 0.0},
}


class BudgetLayer:
    """Departmental software-license budget pools with running spend ledger."""

    CIRCUIT_BREAKER_PCT: float = 1.10  # 110% of forecast triggers freeze

    def __init__(self) -> None:
        self._budgets = deepcopy(DEPARTMENT_BUDGETS)
        self._circuit_breaker_tripped: Dict[str, bool] = {d: False for d in self._budgets}

    def get(self, department: str) -> Optional[Dict[str, float]]:
        return self._budgets.get(department.lower())

    def forecast_for(self, department: str) -> Optional[float]:
        b = self.get(department)
        return b["forecast"] if b else None

    def headroom(self, department: str) -> Optional[float]:
        b = self.get(department)
        if not b:
            return None
        return b["monthly_pool"] - b["spent"]

    def would_overrun(self, department: str, cost: float) -> bool:
        h = self.headroom(department)
        return h is None or cost > h

    def charge(self, department: str, cost: float) -> Dict[str, float]:
        """Add to spent ledger. Called on auto-approved IMPLEMENTED requests."""
        b = self.get(department)
        if not b:
            return {"error": -1}
        b["spent"] += cost
        if b["spent"] > b["forecast"] * self.CIRCUIT_BREAKER_PCT:
            self._circuit_breaker_tripped[department.lower()] = True
        return dict(b)

    def circuit_breaker_active(self, department: str) -> bool:
        return self._circuit_breaker_tripped.get(department.lower(), False)


# ---------------------------------------------------------------------------
# Layer 9: Service Request Registry (Phase 2)
# ---------------------------------------------------------------------------


class ServiceRequestRegistryLayer:
    """Holds LicenseRequestRecord audit objects keyed by request_id."""

    def __init__(self) -> None:
        self._requests: Dict[str, LicenseRequestRecord] = {}

    def add(self, record: LicenseRequestRecord) -> None:
        self._requests[record.request_id] = record

    def get(self, request_id: str) -> Optional[LicenseRequestRecord]:
        return self._requests.get(request_id)

    def get_by_change_id(self, change_id: str) -> Optional[LicenseRequestRecord]:
        for r in self._requests.values():
            if r.change_id == change_id:
                return r
        return None

    def all(self) -> List[LicenseRequestRecord]:
        return list(self._requests.values())


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

services = ServiceCatalogLayer()
cmdb = CMDBLayer(services)
calendar = ChangeCalendarLayer()
policy = PolicyRegistryLayer()
operations = OperationalStateLayer()
kedb = KEDBLayer()
license_catalog = LicenseCatalogLayer()
budget = BudgetLayer()
service_requests = ServiceRequestRegistryLayer()


def reset_state() -> None:
    """Reinitialize all layers — useful for tests/demos that run multiple scenarios."""
    global services, cmdb, calendar, policy, operations, kedb
    global license_catalog, budget, service_requests
    services = ServiceCatalogLayer()
    cmdb = CMDBLayer(services)
    calendar = ChangeCalendarLayer()
    policy = PolicyRegistryLayer()
    operations = OperationalStateLayer()
    kedb = KEDBLayer()
    license_catalog = LicenseCatalogLayer()
    budget = BudgetLayer()
    service_requests = ServiceRequestRegistryLayer()
