"""Assembly of the FinServe Problem Management crew (sequential)."""
from crewai import Crew, Process

from .tasks import task1, task2, task3, task4, task5


def create_problem_crew() -> Crew:
    """5 agents, 5 sequential tasks — ITIL 4 Problem Management lifecycle.

    Stage flow:
        Task1 (Trend Analyst)        → Problem Detection
        Task2 (CMDB Correlator)      → Problem Logging & Classification
        Task3 (RCA Investigator)     → Root Cause Analysis
        Task4 (Known Error Author)   → Known Error Documentation (writes PRB + KE files)
        Task5 (Change Proposer)      → Resolution via Change (writes RFC files)

    Each task receives the structured output of every prior task via the
    ``context`` parameter declared in tasks.py.
    """
    # The agent objects are shared with the tasks (tasks.py already binds them).
    # Crew accepts the full agent list once.
    from .tasks import agents
    return Crew(
        agents=agents,
        tasks=[task1, task2, task3, task4, task5],
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True,
    )
