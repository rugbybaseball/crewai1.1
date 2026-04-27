"""Configuration for the Problem Management crew.

CSV file paths are resolved from environment variables, falling back to the
``data/`` directory at the repo root. Output files (Problem Records, Known
Errors, RFCs) go into ``output/``.
"""
import os
from pathlib import Path

# Repo root = parent of src/
REPO_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = Path(os.environ.get("PM_DATA_DIR", REPO_ROOT / "data"))
OUTPUT_DIR = Path(os.environ.get("PM_OUTPUT_DIR", REPO_ROOT / "output"))

INCIDENTS_CSV = Path(os.environ.get("INCIDENTS_CSV", DATA_DIR / "finserve_incidents_q1_2026.csv"))
CMDB_CSV = Path(os.environ.get("CMDB_CSV", DATA_DIR / "finserve_cmdb.csv"))
CHANGES_CSV = Path(os.environ.get("CHANGES_CSV", DATA_DIR / "finserve_changes.csv"))


def ensure_output_dir() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR
