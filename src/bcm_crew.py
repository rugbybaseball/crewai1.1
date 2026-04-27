from crewai import Crew, Process
from src.agents import create_agents
from src.tasks import task1, task2, task3, task4, task5, task6

def create_bcm_crew():
    """
    Creates a production-grade BCM crew with 6 agents executing 6 sequential tasks.

    Task Flow:
    1. Task1 (Detection Agent) - NIST CSF incident classification
    2. Task3 (SecOps Agent) - Security containment & forensics (parallel to Task2)
    3. Task2 (Impact Agent) - Business impact analysis
    4. Task4 (Recovery Agent) - DR execution & validation
    5. Task5 (Change Manager) - Emergency change management
    6. Task6 (Comms Agent) - Stakeholder communication & regulatory reporting

    Each task builds on prior tasks for context passing and decision making.
    """
    agents = create_agents()
    return Crew(
        agents=agents,
        tasks=[task1, task2, task3, task4, task5, task6],
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True
    )