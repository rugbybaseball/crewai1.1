"""Five sequential Problem Management tasks with context chaining."""
from crewai import Task

from .agents import create_pm_agents

agents = create_pm_agents()
trend_analyst, cmdb_correlator, rca_investigator, known_error_author, change_proposer = agents


# Task 1 — Problem Detection
task1 = Task(
    description=(
        "PROBLEM DETECTION (ITIL 4 Problem Identification phase)\n\n"
        "Surface 3-4 recurring incident patterns in the FinServe Q1 2026 dataset. Execute:\n"
        "1. Call find_patterns with group_by='service+error_code' and min_count=3.\n"
        "2. For each cluster (sorted by incident_count desc), call get_time_distribution "
        "(filter by service AND error_code) to surface temporal regularity.\n"
        "3. Call calculate_impact (same filter) to quantify count, downtime, priority mix.\n"
        "4. Call parse_incidents with search_text='AZ-c' and search_text='month-end' to "
        "discover patterns that error-code grouping alone misses.\n"
        "5. Select the top 3-4 candidate patterns based on incident_count, P1 count, and "
        "evidence strength.\n\n"
        "Do NOT perform root cause analysis here — only enumerate the patterns and the "
        "statistical evidence for each."
    ),
    agent=trend_analyst,
    expected_output=(
        "JSON object with key 'patterns' containing a list of 3-4 candidate clusters. "
        "Each cluster MUST include: pattern_id, services, error_codes, ci_ids, "
        "incident_count, p1_count, sample_incident_ids (3-5 ids), time_distribution "
        "(day_of_week and hour_of_day histograms), first_seen, last_seen, related_changes "
        "(from incident rows), and a one-sentence 'evidence' summary citing counts. "
        "Do not include speculation about root cause."
    ),
)


# Task 2 — Problem Logging & Classification (CMDB enrichment)
task2 = Task(
    description=(
        "PROBLEM LOGGING & CLASSIFICATION (ITIL 4 Configuration Management cross-reference)\n\n"
        "For EVERY pattern from Task 1, enrich with CMDB and change-log context. Execute:\n"
        "1. For each affected CI in the pattern, call query_cmdb — capture tier, owner, "
        "infrastructure, upstream_deps, downstream_deps, AND the free-text 'notes' field "
        "verbatim. The notes field often contains shared-infrastructure details that are "
        "the actual root cause.\n"
        "2. Call map_dependencies on each affected CI (direction='both', depth=2). Note "
        "any reverse dependencies (other CIs that point to this one) — these are common "
        "shared-infrastructure patterns.\n"
        "3. Call query_changes filtered by ci_id for each affected CI; record the changes.\n"
        "4. Call correlate_incidents_changes (window_hours=72) using each pattern's "
        "ci_id and error_code; record the top correlated change ids.\n\n"
        "For each pattern, classify severity (Critical / High / Medium) based on tier "
        "of affected CIs and P1 count."
    ),
    agent=cmdb_correlator,
    expected_output=(
        "JSON object with key 'enriched_patterns' — same patterns from Task 1, each "
        "augmented with: ci_records (full CMDB row including notes verbatim), "
        "dependency_graph (upstream / downstream / reverse), change_history (list of "
        "changes per CI), top_correlated_changes (change ids that precede this pattern's "
        "incidents most often, with hit counts), and severity classification."
    ),
    context=[task1],
)


# Task 3 — Root Cause Analysis (Five Whys)
task3 = Task(
    description=(
        "ROOT CAUSE ANALYSIS (ITIL 4 Problem Control phase)\n\n"
        "For EVERY enriched pattern from Task 2, build a Five Whys causal chain. Execute:\n"
        "1. Call build_timeline (ci_id + error_code) for the chronological sequence.\n"
        "2. Call parse_incidents (ci_id + error_code, limit=20) and READ the "
        "resolution_notes of every linked incident — they contain the responder's clues.\n"
        "3. If CMDB notes from Task 2 reference shared infrastructure (e.g. 'shares "
        "db-ledger-prod connection pool'), call query_cmdb on the OTHER CI mentioned.\n"
        "4. If correlated_changes is non-empty, call query_changes(change_id=...) to read "
        "the change description and confirm the linkage.\n"
        "5. Construct a Five Whys chain (exactly 5 'Why?' answers) that ends in a "
        "process / configuration / change failure — not a symptom. Every Why answer must "
        "cite at least one piece of evidence (incident id, change id, or CMDB note)."
    ),
    agent=rca_investigator,
    expected_output=(
        "JSON object with key 'root_causes' — one entry per pattern. Each entry MUST "
        "include: pattern_id, affected_ci, root_cause (one paragraph naming CIs and "
        "change ids), five_whys (list of exactly 5 strings), timeline (list of "
        "incident/change events with timestamps), and evidence_refs (list of ids "
        "supporting the chain). Do NOT propose fixes here — only explain why."
    ),
    context=[task1, task2],
)


# Task 4 — Known Error Documentation
task4 = Task(
    description=(
        "KNOWN ERROR DOCUMENTATION (ITIL 4 Error Control phase)\n\n"
        "For EVERY root cause from Task 3, produce both a Problem Record and a Known "
        "Error Record. Execute:\n"
        "1. Call create_problem_record with: pattern_id, title (concise problem name), "
        "severity (from Task 2 classification), affected_cis, affected_services, "
        "linked_incidents (full list of incident ids in the pattern), summary "
        "(1 paragraph), status='Known Error'.\n"
        "2. Call create_known_error with: problem_id (from step 1), title, affected_ci, "
        "linked_incidents, root_cause (verbatim from Task 3), five_whys, workaround "
        "(MUST be concrete — e.g. 'Kill the month-end batch job in reporting-engine to "
        "release db-ledger-prod connections', NOT 'restart the service'), permanent_fix "
        "(scoped enough that an RFC can be drafted), evidence_refs.\n\n"
        "Repeat for each pattern. The output of create_known_error includes the path to "
        "the written file in output/."
    ),
    agent=known_error_author,
    expected_output=(
        "JSON object with key 'known_errors' — one entry per pattern, each containing: "
        "ke_id, problem_id, affected_ci, linked_incidents, root_cause, workaround "
        "(concrete and actionable), permanent_fix (concrete), evidence_refs, and the "
        "file paths of the written PRB-*.json and KE-*.md files."
    ),
    context=[task1, task2, task3],
)


# Task 5 — Resolution via Change
task5 = Task(
    description=(
        "RESOLUTION VIA CHANGE (ITIL 4 Change Enablement)\n\n"
        "For EVERY Known Error from Task 4, draft an RFC. Execute:\n"
        "1. Call query_cmdb on the affected_ci to confirm tier and owner — assign the "
        "owning team as the implementer.\n"
        "2. Call create_rfc with: ke_id, title, affected_ci, change_type "
        "('Standard' for low-risk pre-approved patterns, 'Normal' for standard "
        "code/config changes, 'Emergency' only when active production impact is "
        "ongoing), risk (Low / Medium / High aligned with CI tier and impact), "
        "description (specific code/config/infra change), test_plan (list of bullet "
        "items including load testing, regression, staging soak — gates must match the "
        "risk), rollback_plan (list of specific rollback steps), schedule (proposed "
        "implementation window), implementer (the CMDB owner team).\n\n"
        "Repeat for each Known Error."
    ),
    agent=change_proposer,
    expected_output=(
        "JSON object with key 'rfcs' — one entry per Known Error, each containing: "
        "rfc_id, ke_id, affected_ci, change_type, risk, description, test_plan "
        "(>=3 items), rollback_plan (>=2 items), schedule, implementer, and the file "
        "path of the written RFC-*.md file. Conclude with a brief Problem Management "
        "report summary listing every PRB / KE / RFC produced."
    ),
    context=[task3, task4],
)


__all__ = ["task1", "task2", "task3", "task4", "task5"]
