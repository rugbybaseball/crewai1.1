"""
Crew composition. The right task graph depends on the scenario category:

  incident scenarios       -> INCIDENT_TASKS (8 tasks: classify, BIA, contain,
                              recover, emergency CAB technical/risk/decision/PIR, comms)
  standard change          -> STANDARD_CHANGE_TASKS (3 tasks: submit auto-approves
                              via template, implement, PIR)
  normal change            -> NORMAL_CHANGE_TASKS (6 tasks: submit, tech review,
                              risk review, CAB decision, implement, PIR)
  failed_change_rollback   -> NORMAL_CHANGE_TASKS (same graph; the scenario brief
                              instructs the implementer to force_backout=true)
"""
from crewai import Crew, Process

from src.agents import create_agents
from src.tasks import (
    INCIDENT_TASKS,
    NORMAL_CHANGE_TASKS,
    STANDARD_CHANGE_TASKS,
    FAILED_CHANGE_TASKS,
)


# Scenario name -> category. Drives task selection and weighted scoring.
SCENARIO_CATEGORY = {
    # Incident-driven (incident response + emergency CAB)
    "ransomware": "incident",
    "cloud_outage_ddos": "incident",
    "data_breach": "incident",
    "insider_threat": "incident",
    "supply_chain": "incident",
    "cascading_failure": "incident",
    # Pre-approved, low-risk standard changes
    "standard_cert_rotation": "standard",
    # Planned changes that go through full CAB
    "normal_db_upgrade": "normal",
    # Planned change that fails post-checks and exercises the backout path
    "failed_change_rollback": "failed",
}


def _tasks_for_category(category: str):
    return {
        "incident": INCIDENT_TASKS,
        "standard": STANDARD_CHANGE_TASKS,
        "normal": NORMAL_CHANGE_TASKS,
        "failed": FAILED_CHANGE_TASKS,
    }[category]


def category_for_scenario(scenario: str) -> str:
    if scenario not in SCENARIO_CATEGORY:
        raise ValueError(
            f"Unknown scenario '{scenario}'. Known: {sorted(SCENARIO_CATEGORY.keys())}"
        )
    return SCENARIO_CATEGORY[scenario]


def create_bcm_crew(scenario: str = "ransomware"):
    """Create a Crew configured for the given scenario."""
    category = category_for_scenario(scenario)
    agents = create_agents()
    tasks = _tasks_for_category(category)
    return Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True,
    )
